#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <concepts>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "btf/btf.h"
#include "util/fd.h"
#include "util/result.h"

namespace bpftrace {

class BpfProgram;

namespace providers {

class Provider;

// Interface for looking up BTF information.
//
// This can be used by providers during parsing to look up the existence of
// functions, types, etc. The backing implementation is expected to be
// reasonably efficient and cache the loading of BTF, etc.
class BtfLookup {
public:
  virtual ~BtfLookup() = default;

  // Get BTF information for a kernel module or "vmlinux" for kernel.
  //
  // An empty type system is returned if it is not available.
  virtual const btf::Types &get_kernel_btf(
      const std::string &module = "vmlinux") const = 0;

  // Get BTF information for a user binary at the given path.
  //
  // Same behavior as the kernel, an empty type system may be returned.
  virtual const btf::Types &get_user_btf(
      const std::string &binary_path) const = 0;
};

// Operations for a single logical attachpoint.
//
// This is not permitted to have any glob semantics, and must correspond to
// a logical attach point (a single function, a single interval, etc.).
//
// This class may be overriden to include additional metadata required by the
// provider, or it may be used as is.
class AttachPoint {
public:
  // Action indicates what should happen with this attach point. This will
  // result in different calls to the underlying provider, based on the action.
  enum class Action {
    Pre,    // `run` should be called ahead of attaching probes.
    Once,   // `run` should be called after attaching probes.
    Post,   // `run` should be called after detaching probes.
    Manual, // Either `run` or `attach` may be called by invocation.
    Attach, // The probe will have `attach` called at the normal time.
  };
  AttachPoint(const Provider &provider, std::string name = "")
      : provider_(provider), name_(std::move(name)) {};
  virtual ~AttachPoint() = default;

  // Associated provider for this attachpoint.
  const Provider &provider() const
  {
    return provider_;
  }

  // Casts this to the given type.
  template <typename T>
    requires std::derived_from<T, AttachPoint>
  T &as()
  {
    return *static_cast<T *>(this);
  }

  // Canonical target name (within the provider above).
  //
  // This may be dynamically constructed, or it may rely on the static name
  // passed to the constructor above as a convenience.
  virtual std::string name() const
  {
    return name_;
  }

  // Action to be taken.
  virtual Action action() const
  {
    return Action::Attach;
  }

  // Returns an optional type system for the attach point.
  virtual std::optional<bpftrace::btf::Types> type_system() const
  {
    return std::nullopt;
  }

  // Returns the context type for this specific attach point.
  virtual std::optional<bpftrace::btf::AnyType> context_type() const
  {
    return std::nullopt;
  }

  // Returns the expected return type.
  virtual std::optional<bpftrace::btf::AnyType> return_type() const
  {
    return std::nullopt;
  }

  /// BPF program type for this attach point.
  virtual bpf_prog_type prog_type() const
  {
    return BPF_PROG_TYPE_TRACING;
  }

  // This indicates whether the given attachpoint can be used in a multi-attach.
  //
  // This may vary on an attach point-by-attach point basis.
  virtual bool can_multi_attach() const
  {
    return false;
  }

private:
  const Provider &provider_;
  const std::string name_;
};
using AttachPointList = std::vector<std::unique_ptr<AttachPoint>>;

std::ostream &operator<<(std::ostream &out, const AttachPoint &attach_point);

// AttachError may be returned if there is an error attaching.
class AttachError : public ErrorInfo<AttachError> {
public:
  AttachError(std::unique_ptr<AttachPoint> &&attach_point, std::string err)
      : attach_point_(std::move(attach_point)), err_(std::move(err)) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  std::unique_ptr<AttachPoint> attach_point_;
  std::string err_;
};

// Corresponds to an attached program.
//
// Note that the program will remain attached as long as this object exists,
// deleting this object will detach the program.
//
// Like AttachPoint, this can be override by implementations if needed.
class AttachedProbe {
public:
  // Takes ownership of the bpf_link objects and attach points.
  AttachedProbe(struct bpf_link *link, AttachPointList &&attach_points)
      : link_(link), attach_points_(std::move(attach_points)) {};
  virtual ~AttachedProbe();

  int link_fd() const;

  const AttachPointList &attach_points() const
  {
    return attach_points_;
  }

private:
  struct bpf_link *link_;
  AttachPointList attach_points_;
};
using AttachedProbeList = std::vector<std::unique_ptr<AttachedProbe>>;

// ParseError may be returned if there is an error parsing a target.
class ParseError : public ErrorInfo<ParseError> {
public:
  template <typename T>
    requires std::derived_from<T, Provider>
  ParseError(const T *provider, std::string target, std::string err)
      : provider_(static_cast<const Provider *>(provider)),
        target_(std::move(target)),
        err_(std::move(err)){};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  const Provider *provider_;
  std::string target_;
  std::string err_;
};

// Implementation base class for all providers.
//
// Every provider type may override this class and provide custom behavior with
// respect to discovering attachable endpoints, attaching, parsing, etc. Note
// that each provider must have a consistent `bpf_probe_attach_type` and a
// consistent `bpg_prog_type`, as they may be used during compilation.
//
// Each provider must also provide a canonical name, as this will be used during
// compilation as well, but may provide a set of aliases for user convenience.
class Provider {
public:
  Provider(const std::string &name, const std::vector<std::string> &aliases)
      : name_(name), aliases_(aliases) {};
  virtual ~Provider() = default;

  // Returns the canonical name for the provider.
  const std::string &name() const
  {
    return name_;
  }

  // Full set of aliases for the provider.
  const std::vector<std::string> &aliases() const
  {
    return aliases_;
  }

  // Returns a unique identifier for the provider.
  //
  // This is non-static, but will often be called with nullptr.
  virtual uint64_t provider_id() const = 0;

  // Checks if this is the given provider.
  template <typename T>
  bool is() const
  {
    // See `provider_id` above.
    return provider_id() == (static_cast<T *>(nullptr))->provider_id();
  }

  // Parse an attach point string for this provider.
  //
  // This parsing should handle globs and other matching functions and return
  // the full set of attach points. Note that no attempt to attach should be
  // made; these attachpoints can be used for listing or later attachpoint.
  //
  // An optional pid may be provided, which may be used by certain providers to
  // find relevant attachpoints.
  virtual Result<AttachPointList> parse(
      const std::string &str,
      const BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const = 0;

  // Run the specified programs.
  Result<> run(std::unique_ptr<AttachPoint> &attach_point,
               const BpfProgram &prog) const;

  // This should be implemented if running programs is supported.
  virtual Result<> run_single(std::unique_ptr<AttachPoint> &attach_point,
                              const BpfProgram &prog) const;

  // Attach to a specific set of attachpoints with this provider.
  Result<AttachedProbeList> attach(AttachPointList &&attach_points,
                                   const BpfProgram &prog,
                                   std::optional<int> pid = std::nullopt) const;

  // This may be implemented if multi-attach is not supported.
  virtual Result<AttachedProbeList> attach_single(
      std::unique_ptr<AttachPoint> &&attach_point,
      const BpfProgram &prog,
      std::optional<int> pid = std::nullopt) const;

  // This should be implemented if multi-attach is supported.
  //
  // Note that an empty list should return an empty result, which indicates
  // that multi-attach is supported. If multi-attach is not supported, this
  // should return an error indicating as much.
  virtual Result<AttachedProbeList> attach_multi(
      AttachPointList &&attach_points,
      const BpfProgram &prog,
      std::optional<int> pid = std::nullopt) const;

  // Helper method to create an attach point list.
  template <typename T = AttachPoint, typename... Args>
    requires std::derived_from<T, AttachPoint>
  AttachPointList make_list(Args &&...args) const
  {
    AttachPointList result;
    result.emplace_back(
        std::make_unique<T>(*this, std::forward<Args>(args)...));
    return result;
  }
  AttachPointList wrap_list(std::unique_ptr<AttachPoint> &&attach_point) const
  {
    AttachPointList result;
    result.emplace_back(std::move(attach_point));
    return result;
  }

  // Helper method to create an attached probe list.
  template <typename T = AttachedProbe, typename... Args>
    requires std::derived_from<T, AttachedProbe>
  AttachedProbeList make_list(struct bpf_link *link, Args &&...args) const
  {
    AttachedProbeList result;
    result.emplace_back(std::make_unique<T>(link, std::forward<Args>(args)...));
    return result;
  }
  AttachedProbeList wrap_list(
      std::unique_ptr<AttachedProbe> &&attached_probe) const
  {
    AttachedProbeList result;
    result.emplace_back(std::move(attached_probe));
    return result;
  }

private:
  std::string name_;
  std::vector<std::string> aliases_;
};

// ProviderImpl is used for CRTP.
template <typename T>
class ProviderImpl : public Provider {
public:
  ProviderImpl(const std::string &name, const std::vector<std::string> &aliases)
      : Provider(name, aliases) {};

  // See above; a unique identifier per class.
  uint64_t provider_id() const override
  {
    return reinterpret_cast<uint64_t>(&sentinel);
  }

private:
  static inline char sentinel = 0;
};

// ProviderConflict is an error returned when the same provider is registered.
class ProviderConflict : public ErrorInfo<ProviderConflict> {
public:
  ProviderConflict(const Provider *first, std::unique_ptr<Provider> &&second)
      : first_(first), second_(std::move(second)) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  const Provider *first_;
  const std::unique_ptr<Provider> second_;
};

// Merges two attach point lists.
inline AttachPointList merge(AttachPointList &&first, AttachPointList &&second)
{
  for (auto &item : second) {
    first.emplace_back(std::move(item));
  }
  return std::move(first);
}

// Filters an attach point list by a specific provider.
//
// auto [with, without] = filter(orig);
template <typename T>
std::pair<AttachPointList, AttachPointList> filter(
    AttachPointList &&attach_points)
{
  AttachPointList with;
  AttachPointList without;
  for (auto &item : attach_points) {
    if (item->provider().is<T>()) {
      with.emplace_back(std::move(item));
    } else {
      without.emplace_back(std::move(item));
    }
  }
  return { with, without };
}

} // namespace providers
} // namespace bpftrace
