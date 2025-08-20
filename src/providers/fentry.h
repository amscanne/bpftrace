#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

/// Provider for fentry attach points.
class FentryProvider : public ProviderImpl<FentryProvider> {
public:
  FentryProvider(bool is_fexit)
      : ProviderImpl<FentryProvider>(is_fexit ? "fexit" : "fentry", {}),
        is_fexit_(is_fexit) {};

  Result<AttachPointList> parse(
      const std::string &str,
      const BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;

  Result<AttachedProbeList> attach_single(
      std::unique_ptr<AttachPoint> &&attach_point,
      const BpfProgram &prog,
      std::optional<int> pid = std::nullopt) const override;

private:
  bool is_fexit_;
};

} // namespace bpftrace::providers
