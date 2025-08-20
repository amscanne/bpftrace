#include <bpf/libbpf.h>

#include "bpfprogram.h"
#include "log.h"
#include "providers/kprobe.h"
#include "util/strings.h"

namespace bpftrace::providers {

class KprobeAttachPoint : public AttachPoint {
public:
  KprobeAttachPoint(const Provider &provider,
                    const std::string &target,
                    const std::string &func,
                    uint64_t func_offset)
      : AttachPoint(provider),
        target(target),
        func(func),
        func_offset(func_offset) {};

  std::string name() const override
  {
    std::stringstream ss;
    if (!target.empty()) {
      ss << target << ":";
    }
    ss << func;
    if (func_offset != 0) {
      ss << "+" << func_offset;
    }
    return ss.str();
  }

  bpf_prog_type prog_type() const override
  {
    return BPF_PROG_TYPE_KPROBE;
  }

  bool can_multi_attach() const override
  {
    return func_offset == 0 && target.empty();
  }

  const std::string target;
  const std::string func;
  const uint64_t func_offset;
};

Result<AttachPointList> KprobeProvider::parse(
    const std::string &str,
    [[maybe_unused]] const BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto parts = util::split_string(str, ':');
  if (parts.size() > 2) {
    return make_error<ParseError>(this, str, "invalid kprobe format");
  }

  std::string target;
  std::string func = parts.back();
  uint64_t func_offset = 0;
  if (parts.size() == 2) {
    target = parts[0];
  }

  // Handle function+offset syntax.
  auto plus_pos = func.find('+');
  if (plus_pos != std::string::npos) {
    if (is_kretprobe_) {
      return make_error<ParseError>(this, str, "kretprobes cannot use offsets");
    }

    std::string func_name = func.substr(0, plus_pos);
    std::string offset_str = func.substr(plus_pos + 1);

    try {
      func_offset = std::stoull(offset_str, nullptr, 0);
    } catch (const std::exception &) {
      return make_error<ParseError>(this, str, "invalid offset: " + offset_str);
    }

    func = func_name;
  }

  return make_list<KprobeAttachPoint>(target, func, func_offset);
}

Result<AttachedProbeList> KprobeProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  // Use the old fashion single-attach API.
  auto &kprobe_attach_point = attach_point->as<KprobeAttachPoint>();

  struct bpf_kprobe_opts opts = {};
  opts.sz = sizeof(opts);
  opts.offset = kprobe_attach_point.func_offset;
  opts.retprobe = is_kretprobe_;

  auto *link = bpf_program__attach_kprobe_opts(prog.bpf_prog(),
                                               kprobe_attach_point.func.c_str(),
                                               &opts);
  if (!link) {
    return make_error<AttachError>(std::move(attach_point),
                                   "failed to attach kretprobe");
  }

  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

Result<AttachedProbeList> KprobeProvider::attach_multi(
    AttachPointList &&attach_points,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  if (attach_points.empty()) {
    return AttachedProbeList{};
  }

  // Collect function names for multi-attach.
  std::vector<const char *> syms;
  std::vector<std::string> func_names;
  for (auto &attach_point : attach_points) {
    auto &kprobe_attach_point = attach_point->as<KprobeAttachPoint>();
    func_names.push_back(kprobe_attach_point.func);
    syms.push_back(func_names.back().c_str());
  }

  // Set up multi-attach options.
  struct bpf_kprobe_multi_opts opts = {};
  opts.sz = sizeof(opts);
  opts.syms = syms.data();
  opts.cnt = syms.size();
  opts.retprobe = is_kretprobe_;

  auto *link = bpf_program__attach_kprobe_multi_opts(prog.bpf_prog(),
                                                     nullptr,
                                                     &opts);
  if (!link) {
    return make_error<AttachError>(std::move(attach_points[0]),
                                   "failed to attach multi kprobe");
  }

  return make_list<AttachedProbe>(link, std::move(attach_points));
}

} // namespace bpftrace::providers
