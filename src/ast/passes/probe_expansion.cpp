#include "ast/passes/probe_expansion.h"
#include "ast/passes/register_providers.h"
#include "bpftrace.h"
#include "providers/kprobe.h"
#include "providers/provider.h"

namespace bpftrace::ast {

static ExpandedAttachPoints expand(ASTContext &ast, ProviderRegistry &registry)
{
  ExpandedAttachPoints result;
  auto orig_probes = std::move(ast.root->probes);
  ast.root->probes.clear();
  for (auto *probe : orig_probes) {
    if (probe->attach_points.empty()) {
      continue; // Nothing to attach to?
    }
    for (auto *attach_point : probe->attach_points) {
      auto aps = registry.get_all_matching(attach_point->provider,
                                           attach_point->target);
      if (!aps) {
        attach_point->addError()
            << "Unable to expand attach points: " << aps.takeError();
        continue;
      }
      if (aps->empty()) {
        continue; // Nothing expanded.
      }
      if (aps->size() == 1 && aps->at(0).second.size() == 1) {
        // Use the original probe, rewritting the attach point.
        auto &[provider, ap] = aps->at(0);
        attach_point->provider = provider->name();
        attach_point->target = ap[0]->name();
        ast.root->probes.push_back(probe);
        result.attach_points.emplace(probe, std::move(ap));
        continue;
      }
      // Expand all probes into single attach points.
      for (auto &pair : *aps) {
        auto &[provider, provider_aps] = pair;
        for (auto &ap : provider_aps) {
          auto *new_attach_point = ast.make_node<AttachPoint>(
              provider->name(), ap->name(), Location(attach_point->loc));
          auto *new_probe = ast.make_node<Probe>(
              AttachPointList({ new_attach_point }),
              clone(ast, probe->block, Location(attach_point->loc)),
              Location(probe->loc));
          ast.root->probes.push_back(new_probe);
          result.attach_points.emplace(new_probe, std::move(ap));
        }
      }
    }
  }
  return result;
}

static Probe *find_matching_retprobe(Probe *probe, ExpandedAttachPoints &result)
{
  auto it = result.attach_points.find(probe);
  assert(it != result.attach_points.end());
  const auto &pair = it->second;
  const auto &[provider, attach_point] = pair;
  if (!provider->is<providers::KprobeProvider>()) {
    return nullptr; // Not matchable.
  }
  for (const auto &[other, other_pair] : result.attach_points) {
    const auto &[other_provider, other_attach_point] = other_pair;
    if (other_provider->is<providers::KretprobeProvider>() &&
        attach_point->name() == other_attach_point->name()) {
      return other; // Matched!
    }
  }
  return nullptr;
}

static void reduce_sessions(ASTContext &ast,
                            ProviderRegistry &registry,
                            ExpandedAttachPoints &result)
{
  const auto *session_provider = registry.lookup<providers::KprobeProvider>();
  if (session_provider == nullptr) {
    return;
  }

  for (const auto &[probe, _] : result.attach_points) {
    auto *retprobe = find_matching_retprobe(probe, result);
    if (retprobe == nullptr) {
      continue; // Not reducable.
    }

    // Check to see if this is a legal session probe.
    auto session = session_provider->parse(probe->attach_points[0]->target,
                                           providers::BtfLookup{});
    if (!session || session->size() != 1) {
      continue; // Not a valid session target, or ambiguous?
    }

    // Ensure that this is not included.
    if (result.attach_points.contains(retprobe)) {
      result.attach_points.erase(retprobe);
    }

    // Modify the block of this probe, to have a new attach point and a new
    // if that gates session. This will refer to the session return builtin.
    auto *expr = ast_.make_node<IfExpr>(
        ast_.make_node<Call>("__session_is_return",
                             ExpressionList{},
                             Location(probe.block->loc)),
        retprobe->block,
        probe.block,
        Location(probe.block->loc));
    probe->block = ast.make_node<BlockExpr>(StatementList{},
                                            expr,
                                            Location(probe->block->loc));
    result.attach_points[probe].first = session_provider;
    result.attach_points[probe].second = std::move(session->at(0));
  }
}

struct ReduceKey {
  const providers::Provider *provider;
  Probe *probe;
};

struct BlockComparison {
  bool operator()(ReduceKey *const &a, ReduceKey *const &b) const
  {
    // Checks if the blocks are the same and the provider is the same.
    return a->provider->name() == b->provider->name() &&
           *a->probe->block == *b->probe->block;
  }
};

Pass CreateProbeExpansionPass()
{
  auto fn = [](ASTContext &ast,
               BPFtrace &bpftrace,
               ProviderRegistry &registry) -> ExpandedAttachPoints {
    auto result = expand(ast, registry);
    if (bpftrace.feature_->has_kprobe_session()) {
      reduce_sessions(ast, registry, result);
    }
    return result;
  };

  return Pass::create("ProbeExpansion", fn);
}

Pass CreateProbeMergePass()
{
  auto fn = [](ASTContext &ast,
               ExpandedAttachPoints &expanded) -> ReducedAttachPoints {
    // Deduplicate all identifical programs.
    std::map<ReduceKey,
             std::pair<providers::Provider *, providers::AttachPointList>,
             BlockComparison>
        blocks;
    for (auto &[probe, pair] : expanded.attach_points) {
      auto &[provider, target] = pair;
      auto key = ReduceKey{
        .provider = provider,
        .probe = probe,
      };
      auto it = blocks.find(key);
      if (it == blocks.end()) {
        // Add a new entry, since this program is unique.
        blocks.emplace(probe, std::make_pair(provider, std::move(target)));
      } else {
        // Just add to the list of existing attach points.
        it->second.second.emplace_back(std::move(target));
      }
    }

    // Update the program and construct our result.
    ReducedAttachPoints result;
    ast.root->probes.clear();
    for (auto &[key, pair] : blocks) {
      ast.root->probes.push_back(key.probe);
      result.attach_points.emplace(key.probe, std::move(pair));
    }
    return result;
  };

  return Pass::create("ProbeMerge", fn);
}

} // namespace bpftrace::ast
