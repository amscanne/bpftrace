#include "providers/iter.h"
#include "bpfprogram.h"
#include "log.h"
#include "util/strings.h"

namespace bpftrace::providers {

Result<std::vector<std::unique_ptr<AttachPoint>>> IterProvider::parse(
    const std::string &str,
    [[maybe_unused]] const BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  return make_list<AttachPoint>(str);
}

Result<AttachedProbeList> IterProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto *link = bpf_program__attach_iter(prog.bpf_prog(), nullptr);
  if (!link) {
    return make_error<AttachError>(std::move(attach_point),
                                   "failed to attach iter");
  }

  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

} // namespace bpftrace::providers
