#pragma once

#include <map>

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "providers/provider.h"

namespace bpftrace::ast {

class ExpandedAttachPoints : public ast::State<"expanded-attach-points"> {
public:
  // This is the fully expanded set of attach points. For every probe in the
  // program, there will be a unique attach point specified. This attach point
  // may be used for the context type, the return type, the program type, and
  // other relevant metadata.
  std::map<Probe *,
           std::pair<const providers::Provider *,
                     std::unique_ptr<providers::AttachPoint>>>
      attach_points;

  // Because probes are uniquely associated with a single provider and single
  // attach point, we can check for the provider type for a given probe. This
  // is a common path, and therefore a convenience function is provided.
  template <typename T>
  bool is(Probe *probe) const
  {
    auto it = attach_points.find(probe);
    if (it == attach_points.end()) {
      return false;
    }
    const providers::Provider *provider = it->second.first;
    return provider->is<T>();
  }
};

class ReducedAttachPoints : public ast::State<"reduced-attach-points"> {
public:
  // This is the set of attach points that have been determined to be
  // associated with each unique program. These are already grouped by
  // the specific attachpoint provider, so all attach points in the list
  // will have identical types, program types, etc.
  std::map<Probe *,
           std::pair<const providers::Provider *, providers::AttachPointList>>
      attach_points;
};

Pass CreateProbeExpansionPass();
Pass CreateProbeMergePass();

} // namespace bpftrace::ast
