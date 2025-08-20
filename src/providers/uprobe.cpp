#include <sstream>
#include <unordered_map>

#ifdef HAVE_BLAZESYM
#include <blazesym.h>
#endif

#include "bpfprogram.h"
#include "log.h"
#include "providers/uprobe.h"
#include "util/strings.h"

namespace bpftrace::providers {

class UprobeAttachPoint : public AttachPoint {
public:
  UprobeAttachPoint(const Provider &provider,
                    const std::string &target,
                    const std::string &func,
                    uint64_t func_offset,
                    uint64_t address)
      : AttachPoint(provider),
        target(target),
        func(func),
        func_offset(func_offset),
        address(address) {};

  std::string name() const override
  {
    std::stringstream ss;
    ss << target << ":" << func;
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
    return true;
  }

  const std::string target;
  const std::string func;
  const uint64_t func_offset;
  const uint64_t address;
};

Result<AttachPointList> UprobeProvider::parse(
    const std::string &str,
    [[maybe_unused]] const BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto parts = util::split_string(str, ':');
  if (parts.size() != 3) {
    return make_error<ParseError>(this, str, "invalid uprobe format");
  }

  std::string target = parts[1];
  std::string func = parts[2];
  uint64_t func_offset = 0;
  uint64_t address = 0;

  // Handle function+offset syntax.
  auto plus_pos = func.find('+');
  if (plus_pos != std::string::npos) {
    if (is_uretprobe_) {
      return make_error<ParseError>(this, str, "uretprobes cannot use offsets");
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

  return make_list<UprobeAttachPoint>(target, func, func_offset, address);
}

#ifdef HAVE_BLAZESYM
static std::optional<uint64_t> resolve_symbol_blazesym(
    const std::string &target,
    const std::string &func,
    uint64_t func_offset)
{
  // Use inspector to get symbol info for symbol address lookup.
  auto *inspector = blaze_inspector_new();
  if (!inspector) {
    return std::nullopt;
  }

  blaze_inspect_elf_src src = {
    .type_size = sizeof(src),
    .path = target.c_str(),
    .debug_syms = true,
  };

  const char *names[] = { func.c_str() };
  const auto *sym_infos = blaze_inspect_syms_elf(inspector, &src, names, 1);

  if (!sym_infos || !sym_infos[0]) {
    if (sym_infos) {
      blaze_inspect_syms_free(sym_infos);
    }
    blaze_inspector_free(inspector);
    return std::nullopt;
  }

  uint64_t addr = sym_infos[0]->addr;
  uint64_t offset = addr + func_offset;

  blaze_inspect_syms_free(sym_infos);
  blaze_inspector_free(inspector);

  return offset;
}
#endif

Result<AttachedProbeList> UprobeProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    std::optional<int> pid) const
{
  auto &uprobe_attach_point = attach_point->as<UprobeAttachPoint>();

#ifdef HAVE_BLAZESYM
  auto offset_result = resolve_symbol_blazesym(uprobe_attach_point.target,
                                               uprobe_attach_point.func,
                                               uprobe_attach_point.func_offset);
  if (!offset_result) {
    return make_error<AttachError>(std::move(attach_point),
                                   "failed to resolve symbol " +
                                       uprobe_attach_point.func);
  }
  uint64_t offset = *offset_result;
#else
  // Fallback for systems without blazesym
  uint64_t offset = uprobe_attach_point.func_offset;
#endif

  // Use libbpf to attach the uprobe.
  struct bpf_uprobe_opts opts = {};
  opts.sz = sizeof(opts);
  opts.retprobe = is_uretprobe_;

  auto *link = bpf_program__attach_uprobe_opts(
      prog.bpf_prog(),
      pid.value_or(-1),
      uprobe_attach_point.target.c_str(),
      offset,
      &opts);

  if (!link) {
    return make_error<AttachError>(std::move(attach_point),
                                   "failed to attach uprobe");
  }

  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

Result<AttachedProbeList> UprobeProvider::attach_multi(
    AttachPointList &&attach_points,
    const BpfProgram &prog,
    std::optional<int> pid) const
{
  if (attach_points.empty()) {
    return AttachedProbeList{};
  }

  // Group attach points by target binary for efficient multi-attach.
  std::unordered_map<std::string, AttachPointList> targets;
  for (auto &attach_point : attach_points) {
    auto &usdt_attach_point = attach_point->as<UprobeAttachPoint>();
    std::string target = usdt_attach_point.target; // Take a copy.
    targets[target].emplace_back(std::move(attach_point));
  }

  AttachedProbeList results;
  for (auto &[target, attach_points] : targets) {
    // Collect function symbols for multi-attach.
    std::vector<const char *> syms;
    std::vector<std::string> func_names;
    for (auto &attach_point : attach_points) {
      auto &usdt_attach_point = attach_point->as<UprobeAttachPoint>();
      func_names.push_back(usdt_attach_point.func);
      syms.push_back(func_names.back().c_str());
    }

    // Set up multi-attach options.
    struct bpf_uprobe_multi_opts opts = {};
    opts.sz = sizeof(opts);
    opts.syms = syms.data();
    opts.cnt = syms.size();
    opts.retprobe = is_uretprobe_;

    auto *link = bpf_program__attach_uprobe_multi(
        prog.bpf_prog(), pid.value_or(-1), target.c_str(), nullptr, &opts);
    if (!link) {
      return make_error<AttachError>(std::move(attach_points[0]),
                                     "failed to attach multi uprobe");
    }
    results.emplace_back(
        std::make_unique<AttachedProbe>(link, std::move(attach_points)));
  }

  return results;
}

} // namespace bpftrace::providers
