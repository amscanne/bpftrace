<<<<<<< HEAD:src/ast/passes/ap_probe_expansion.cpp
#include "ast/passes/ap_probe_expansion.h"

#include <algorithm>

#include "ast/visitor.h"
=======
#include "ast/passes/probe_expansion.h"
#include "ast/passes/register_providers.h"
>>>>>>> 72046fd7 (inprog):src/ast/passes/probe_expansion.cpp
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
        probe.block->loc,
        ast_.make_node<Call>(probe.block->loc,
                             "__session_is_return",
                             ExpressionList{}),
        retprobe->block,
<<<<<<< HEAD:src/ast/passes/ap_probe_expansion.cpp
        probe.block);
    auto *stmt = ast_.make_node<ExprStatement>(probe.block->loc, expr);

    probe.block = ast_.make_node<BlockExpr>(probe.block->loc,
                                            StatementList({ stmt }),
                                            ast_.make_node<None>(
                                                probe.block->loc));

    expansion_result_.set_expansion(*probe.attach_points[0],
                                    ExpansionType::SESSION);

    std::erase(ast_.root->probes, retprobe);
  }
}

class ProbeAndApExpander : public Visitor<ProbeAndApExpander> {
public:
  ProbeAndApExpander(ASTContext &ast,
                     BPFtrace &bpftrace,
                     ExpansionResult &result)
      : ast_(ast), bpftrace_(bpftrace), result_(result)
  {
  }

  void expand();

  using Visitor<ProbeAndApExpander>::visit;
  void visit(Program &prog);
  void visit(AttachPointList &aps);

private:
  uint64_t probe_count_ = 0;

  ASTContext &ast_;
  BPFtrace &bpftrace_;
  ExpansionResult &result_;
};

void ProbeAndApExpander::expand()
{
  visit(*ast_.root);
}

void ProbeAndApExpander::visit(Program &prog)
{
  // Expand attachpoints first.
  Visitor<ProbeAndApExpander>::visit(prog);

  // Expand probes.
  ProbeList new_probe_list;
  for (auto *probe : prog.probes) {
    if (probe->attach_points.size() < 2) {
      new_probe_list.emplace_back(probe);
    } else {
      for (auto *ap : probe->attach_points) {
        auto *new_probe = ast_.make_node<Probe>(
            probe->loc,
            AttachPointList{ ap },
            clone(ast_, probe->block->loc, probe->block));
        new_probe_list.emplace_back(new_probe);
      }
    }
  }

  prog.probes = std::move(new_probe_list);
}

void ProbeAndApExpander::visit(AttachPointList &aps)
{
  const auto max_bpf_progs = bpftrace_.config_->max_bpf_progs;

  AttachPointList new_aps;
  for (auto *ap : aps) {
    auto probe_type = probetype(ap->provider);
    auto expansion = result_.get_expansion(*ap);
    switch (expansion) {
      case ExpansionType::FULL: {
        auto matches = bpftrace_.probe_matcher_->get_matches_for_ap(*ap);

        probe_count_ += matches.size();
        if (probe_count_ > max_bpf_progs) {
          auto &err = ap->addError();
          err << "Your program is trying to generate more than "
              << std::to_string(probe_count_)
              << " BPF programs, which exceeds the current limit of "
              << std::to_string(max_bpf_progs);
          err.addHint() << "You can increase the limit through the "
                           "BPFTRACE_MAX_BPF_PROGS "
                           "environment variable.";
          return;
        }

        for (const auto &match : matches) {
          new_aps.push_back(ap->create_expansion_copy(ast_, match));
        }
        break;
      }

      case ExpansionType::SESSION:
      case ExpansionType::MULTI: {
        auto matches = bpftrace_.probe_matcher_->get_matches_for_ap(*ap);
        if (util::has_wildcard(ap->target)) {
          // If we have a wildcard in the target path, we need to generate one
          // attach point per expanded target
          assert(probe_type == ProbeType::uprobe ||
                 probe_type == ProbeType::uretprobe);

          std::unordered_map<std::string, AttachPoint *> new_aps_by_target;
          for (const auto &func : matches) {
            auto *match_ap = ap->create_expansion_copy(ast_, func);
            // Reset the original (possibly wildcarded) function name
            auto expanded_func = match_ap->func;
            match_ap->func = ap->func;

            auto new_ap = new_aps_by_target.emplace(match_ap->target, match_ap);
            result_.add_expanded_func(*new_ap.first->second,
                                      match_ap->target + ":" + expanded_func);
          }
          for (auto &[_, new_ap] : new_aps_by_target)
            new_aps.push_back(std::move(new_ap));
        } else if (!matches.empty()) {
          result_.set_expanded_funcs(*ap, std::move(matches));
          new_aps.push_back(ap);
        }
        break;
      }
      case ExpansionType::NONE: {
        new_aps.push_back(ap);
        break;
      }
    }
=======
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
>>>>>>> 72046fd7 (inprog):src/ast/passes/probe_expansion.cpp
  }
};

Pass CreateProbeAndApExpansionPass()
{
<<<<<<< HEAD:src/ast/passes/ap_probe_expansion.cpp
  auto fn = [](ASTContext &ast, BPFtrace &bpftrace) {
    ExpansionAnalyser analyser(bpftrace);
    auto result = analyser.analyse(*ast.root);

    SessionExpander session_expander(ast, bpftrace, result);
    session_expander.visit(*ast.root);

    ProbeAndApExpander expander(ast, bpftrace, result);
    expander.expand();

=======
  auto fn = [](ASTContext &ast,
               BPFtrace &bpftrace,
               ProviderRegistry &registry) -> ExpandedAttachPoints {
    auto result = expand(ast, registry);
    if (bpftrace.feature_->has_kprobe_session()) {
      reduce_sessions(ast, registry, result);
    }
>>>>>>> 72046fd7 (inprog):src/ast/passes/probe_expansion.cpp
    return result;
  };

  return Pass::create("ProbeAndApExpansion", fn);
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
