#include <bpf/libbpf.h>

#include "bpfprogram.h"
#include "providers/rawtracepoint.h"

namespace bpftrace::providers {

// Note: there are several prefixes for raw tracepoint BTF functions.
// "__probestub_" seems to be the most accurate in terms of getting the params
// but it wasn't added until May 2023 so older kernels might not have it,
// which is why we also check "__traceiter_" (as needed).
// "btf_trace_" prefix, which is what the kernel uses for raw tracepoints, we
// use in bpfprogram.cpp to validate if we can attach to this raw tracepoint.
// The BTF for "btf_trace_" is a typedef that eventually resolves to a
// FUNC_PROTO but the params for this do not have names, which is what we need.
// "__probestub_" was added here:
// https://lore.kernel.org/all/168507471874.913472.17214624519622959593.stgit@mhiramat.roam.corp.google.com/
// "__traceiter_" was added here:
// https://lore.kernel.org/all/20200908105743.GW2674@hirez.programming.kicks-ass.net/
static const std::vector<std::string_view> RT_BTF_PREFIXES = { "__probestub_",
                                                               "__traceiter_" };

Result<AttachPointList> RawTracepointProvider::parse(
    const std::string &str,
    [[maybe_unused]] BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  return make_list<SimpleAttachPoint>(str);
}

Result<AttachedProbeList> RawTracepointProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto *link = bpf_program__attach_raw_tracepoint(prog.bpf_prog(),
                                                  attach_point->name().c_str());
  if (!link) {
    return make_error<AttachError>(this,
                                   std::move(attach_point),
                                   "failed to attach rawtracepoint");
  }

  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

} // namespace bpftrace::providers
