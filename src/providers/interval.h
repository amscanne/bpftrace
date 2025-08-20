#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

/// Provider for interval (timer-based) attach points.
class IntervalProvider : public ProviderImpl<IntervalProvider> {
public:
  IntervalProvider() : ProviderImpl<IntervalProvider>("interval", { "i" }) {};

  Result<AttachPointList> parse(
      const std::string &str,
      const BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;

  Result<AttachedProbeList> attach_single(
      std::unique_ptr<AttachPoint> &&attach_point,
      const BpfProgram &prog,
      std::optional<int> pid = std::nullopt) const override;
};

} // namespace bpftrace::providers
