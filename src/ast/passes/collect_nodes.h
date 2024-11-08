#pragma once

#include <functional>
#include <vector>

#include "ast/visitor.h"

namespace bpftrace::ast {

/*
 * CollectNodes
 *
 * Recurses into the provided node and builds a list of all descendants of the
 * requested type which match a predicate.
 */
template <typename NodeT>
class CollectNodes : public Visitor<CollectNodes<NodeT>> {
public:
  CollectNodes() : pred_([](const auto &) { return true; })
  {
  }
  CollectNodes(std::function<bool(const NodeT &)> pred) : pred_(pred)
  {
  }

  const std::vector<std::reference_wrapper<NodeT>> &nodes() const
  {
    return nodes_;
  }

  // Override just the method for the specific node type that we would like to
  // visit. The super class will handle all the other traversal.
  void visit(NodeT &node)
  {
    if (pred_(node)) {
      nodes_.push_back(node);
    }
    Visitor<CollectNodes<NodeT>>::visit(node);
  }

private:
  std::vector<std::reference_wrapper<NodeT>> nodes_;
  std::function<bool(const NodeT &)> pred_;
};

} // namespace bpftrace::ast
