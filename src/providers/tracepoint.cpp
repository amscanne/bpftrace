#include "providers/tracepoint.h"
#include "bpfprogram.h"
#include "log.h"
#include "util/strings.h"
#include "util/wildcard.h"

namespace bpftrace::providers {

class TracepointAttachPoint : public AttachPoint {
public:
  TracepointAttachPoint(const Provider &provider,
                        const std::string &category,
                        const std::string &tp_name)
      : AttachPoint(provider), category(category), tp_name(tp_name) {};

  std::string name() const override
  {
    if (category.empty()) {
      return tp_name;
    }
    return category + ":" + tp_name;
  }

  bpf_prog_type prog_type() const override
  {
    return BPF_PROG_TYPE_TRACEPOINT;
  }

  const std::string category;
  const std::string tp_name;
};

Result<AttachPointList> TracepointProvider::parse(
    const std::string &str,
    [[maybe_unused]] const BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto parts = util::split_string(str, ':');
  if (parts.size() > 2) {
    return make_error<ParseError>(this, str, "invalid tracepoint format");
  }
  auto func = parts.back();
  std::string category;
  if (parts.size() > 1) {
    category = parts[0];
  }

  return make_list<TracepointAttachPoint>(category, func);
}

Result<AttachedProbeList> TracepointProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  const auto &tp_attach_point = attach_point->as<TracepointAttachPoint>();

  // Use libbpf to attach the tracepoint.
  auto *link = bpf_program__attach_tracepoint(prog.bpf_prog(),
                                              tp_attach_point.category.c_str(),
                                              tp_attach_point.tp_name.c_str());

  if (!link) {
    return make_error<AttachError>(std::move(attach_point),
                                   "failed to attach tracepoint");
  }
  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

} // namespace bpftrace::providers
