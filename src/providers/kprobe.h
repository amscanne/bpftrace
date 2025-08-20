#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

/// Provider for kprobe and kretprobe attach points
class KprobeProvider : public ProviderImpl<KprobeProvider> {
public:
  KprobeProvider(bool is_kretprobe)
      : ProviderImpl<KprobeProvider>(is_kretprobe ? "kretprobe" : "kprobe",
                                     { is_kretprobe ? "k" : "kr" }),
        is_kretprobe_(is_kretprobe) {};

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
  bool is_kretprobe_;
};

} // namespace bpftrace::providers
