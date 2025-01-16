#pragma once

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "config.h"
#include "log.h"

namespace bpftrace {
namespace ast {

class NodeCounter : public Visitor<NodeCounter> {
public:
  explicit NodeCounter(ASTContext &ctx) : Visitor<NodeCounter>(ctx)
  {
  }

  void preVisit([[maybe_unused]] Node &node)
  {
    count_++;
  }

  size_t get_count()
  {
    return count_;
  };

private:
  size_t count_ = 0;
};

inline Pass CreateCounterPass()
{
  auto fn = [](PassContext &ctx) {
    NodeCounter c(ctx.ast_ctx);
    c.visitAll(*ctx.ast_ctx.root);
    auto node_count = c.get_count();
    auto max = ctx.b.max_ast_nodes_;
    LOG(V1) << "AST node count: " << node_count;
    if (node_count >= max) {
      LOG(ERROR) << "node count (" << node_count << ") exceeds the limit ("
                 << max << ")";
      return PassResult::Error("NodeCounter", "node count exceeded");
    }
    return PassResult::Success();
  };
  return Pass("NodeCounter", fn);
}

} // namespace ast
} // namespace bpftrace
