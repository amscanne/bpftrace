#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

// Common base for special providers.
class SpecialProvider : public ProviderImpl<SpecialProvider> {
public:
  SpecialProvider(const std::string &name,
                  const std::vector<std::string> &aliases,
                  AttachPoint::Action action)
      : ProviderImpl<SpecialProvider>(name, aliases), action_(action) {};

  Result<AttachPointList> parse(
      const std::string &str,
      const BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;

  AttachPoint::Action action()
  {
    return action_;
  }

  Result<> run_single(std::unique_ptr<AttachPoint> &attach_point,
                      const BpfProgram &prog) const override;

private:
  AttachPoint::Action action_;
};

// Provider for begin probes.
class BeginProvider : public SpecialProvider {
public:
  BeginProvider() : SpecialProvider("begin", {}, AttachPoint::Action::Pre) {};
};

// Provider for end probes.
class EndProvider : public SpecialProvider {
public:
  EndProvider() : SpecialProvider("begin", {}, AttachPoint::Action::Post) {};
};

// Provider for self probes.
class SelfProvider : public SpecialProvider {
public:
  SelfProvider() : SpecialProvider("self", {}, AttachPoint::Action::Manual) {};

  Result<AttachPointList> parse(
      const std::string &str,
      const BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;
};

} // namespace bpftrace::providers
