#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

/// Provider for uprobe and uretprobe attach points.
class UprobeProvider : public ProviderImpl<UprobeProvider> {
public:
  UprobeProvider(bool is_uretprobe)
      : ProviderImpl<UprobeProvider>(is_uretprobe ? "uretprobe" : "uprobe",
                                     { is_uretprobe ? "ur" : "u" }),
        is_uretprobe_(is_uretprobe) {};

  Result<AttachPointList> parse(
      const std::string &str,
      const BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;

  Result<AttachedProbeList> attach_single(
      std::unique_ptr<AttachPoint> &&attach_point,
      const BpfProgram &prog,
      std::optional<int> pid = std::nullopt) const override;

  Result<AttachedProbeList> attach_multi(
      AttachPointList &&attach_points,
      const BpfProgram &prog,
      std::optional<int> pid = std::nullopt) const override;

private:
  bool is_uretprobe_;
};

} // namespace bpftrace::providers
