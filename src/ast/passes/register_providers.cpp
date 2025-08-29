#include <algorithm>
#include <vector>

#include "ast/passes/register_providers.h"
#include "providers/benchmark.h"
#include "providers/fentry.h"
#include "providers/interval.h"
#include "providers/kprobe.h"
#include "providers/perf.h"
#include "providers/profile.h"
#include "providers/rawtracepoint.h"
#include "providers/special.h"
#include "providers/tracepoint.h"
#include "providers/uprobe.h"
#include "providers/usdt.h"
#include "providers/watchpoint.h"
#include "util/wildcard.h"

namespace bpftrace::ast {

using namespace bpftrace::providers;

const Provider *ProviderRegistry::lookup(const std::string &name)
{
  auto it = providers_by_name_.find(name);
  if (it != providers_by_name_.end()) {
    return it->second.get();
  }
  auto aliased_it = aliases_to_provider_.find(name);
  if (aliased_it != aliases_to_provider_.end()) {
    return aliased_it->second;
  }
  return nullptr; // Nothing.
}

Result<> ProviderRegistry::add(std::unique_ptr<Provider> &&provider)
{
  const std::string primary_name = provider->name();
  const auto &aliases = provider->aliases();

  // Check for conflicts with primary name.
  const auto *other = lookup(primary_name);
  if (other) {
    return make_error<ProviderConflict>(other, std::move(provider));
  }

  // Check for conflicts with aliases.
  for (const auto &alias : aliases) {
    const auto *other_aliased = lookup(alias);
    if (other_aliased) {
      return make_error<ProviderConflict>(other_aliased, std::move(provider));
    }
  }

  // Register the provider.
  Provider *raw_provider = provider.get();
  providers_by_name_[primary_name] = std::move(provider);
  for (const auto &alias : aliases) {
    aliases_to_provider_[alias] = raw_provider;
  }

  return OK();
}

Result<std::vector<std::pair<Provider *, AttachPointList>>> ProviderRegistry::
    get_all_matching(const std::string &provider_glob,
                     const std::string &target_glob,
                     const BtfLookup &btf) const
{
  bool start_wildcard, end_wildcard;
  auto tokens = util::get_wildcard_tokens(provider_glob,
                                          start_wildcard,
                                          end_wildcard);

  // Collect the set of providers that we will query.
  std::vector<Provider *> providers;
  for (const auto &pair : providers_by_name_) {
    if (util::wildcard_match(
            pair.first, tokens, start_wildcard, end_wildcard)) {
      providers.push_back(pair.second.get());
    }
  }
  for (const auto &pair : aliases_to_provider_) {
    if (util::wildcard_match(
            pair.first, tokens, start_wildcard, end_wildcard) &&
        std::ranges::find(providers, pair.second) == providers.end()) {
      providers.push_back(pair.second);
    }
  }

  // Grab all matching targets.
  std::vector<std::pair<Provider *, AttachPointList>> results;
  for (auto *p : providers) {
    auto targets = p->parse(target_glob, btf);
    if (!targets) {
      return targets.takeError();
    }
    results.emplace_back(p, std::move(*targets));
  }
  return results;
}

Pass CreateRegisterProvidersPass()
{
  return Pass::create("RegisterProviders", []() -> Result<ProviderRegistry> {
    std::vector<std::function<std::unique_ptr<Provider>()>>
        provider_factories = {
          []() { return std::make_unique<BenchmarkProvider>(); },
          []() { return std::make_unique<FentryProvider>(); },
          []() { return std::make_unique<FexitProvider>(); },
          []() { return std::make_unique<RawTracepointProvider>(); },
          []() { return std::make_unique<TracepointProvider>(); },
          []() { return std::make_unique<KprobeProvider>(); },
          []() { return std::make_unique<KretprobeProvider>(); },
          []() { return std::make_unique<KsessionProvider>(); },
          []() { return std::make_unique<UprobeProvider>(); },
          []() { return std::make_unique<UretprobeProvider>(); },
          []() { return std::make_unique<BeginProvider>(); },
          []() { return std::make_unique<EndProvider>(); },
          []() { return std::make_unique<SelfProvider>(); },
          []() { return std::make_unique<IntervalProvider>(); },
          []() { return std::make_unique<ProfileProvider>(); },
          []() { return std::make_unique<PerfProvider>(); },
          []() { return std::make_unique<UsdtProvider>(); },
          []() { return std::make_unique<WatchpointProvider>(); },
        };

    ProviderRegistry registry;
    for (const auto &factory : provider_factories) {
      auto result = registry.add(factory());
      if (!result) {
        return result.takeError();
      }
    }
    return registry;
  });
}

} // namespace bpftrace::ast
