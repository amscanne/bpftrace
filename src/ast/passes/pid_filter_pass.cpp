#include "ast/passes/pid_filter_pass.h"
#include "ast/ast.h"
#include "ast/passes/probe_expansion.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class PidFilterPass : public Visitor<PidFilterPass> {
public:
  explicit PidFilterPass(ASTContext &ast, ExpandedAttachPoints &expanded)
      : ast_(ast), expanded_(expanded)
  {
  }

  using Visitor<PidFilterPass>::visit;
  void visit(Probe &probe);

private:
  ASTContext &ast_;
  ExpandedAttachPoints &expanded_;
};

} // namespace

static BlockExpr *create_pid_filter(ASTContext &ast, BlockExpr *orig_block)
{
  return ast.make_node<BlockExpr>(
      StatementList({}), // All in the expression below.
      ast.make_node<IfExpr>(
          ast.make_node<Binop>(
              ast.make_node<Builtin>("pid", Location(orig_block->loc)),
              Operator::NE,
              ast.make_node<Call>(
                  "getopt",
                  ExpressionList(
                      { ast.make_node<String>("pid", Location(orig_block->loc)),
                        ast.make_node<Integer>(0, Location(orig_block->loc)) }),
                  Location(orig_block->loc)),
              Location(orig_block->loc)),
          ast.make_node<None>(Location(orig_block->loc)), // Empty.
          orig_block,
          Location(orig_block->loc)),
      Location(orig_block->loc));
}

void PidFilterPass::visit(Probe &probe)
{
  if (expanded_.attach_points[&probe].first->uses_pid()) {
    probe.block = create_pid_filter(ast_, probe.block);
    return;
  }
}

Pass CreatePidFilterPass()
{
  return Pass::create("PidFilter",
                      [](ASTContext &ast, ExpandedAttachPoints &expanded) {
                        auto pid_filter = PidFilterPass(ast, expanded);
                        pid_filter.visit(ast.root);
                      });
};

} // namespace bpftrace::ast
