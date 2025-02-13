#include "return_path_analyser.h"
#include "log.h"

namespace bpftrace::ast {

bool ReturnPathAnalyser::visit(Program &prog)
{
  for (Subprog *subprog : prog.functions) {
    if (!visit(*subprog))
      return false;
  }
  return true;
}

bool ReturnPathAnalyser::visit(Subprog &subprog)
{
  if (subprog.return_type.IsVoidTy())
    return true;

  for (Statement *stmt : subprog.stmts) {
    if (visit(*stmt))
      return true;
  }
  LOG(ERROR, subprog.loc, err_) << "Not all code paths returned a value";
  return false;
}

bool ReturnPathAnalyser::visit(Jump &jump)
{
  return jump.ident == JumpType::RETURN;
}

bool ReturnPathAnalyser::visit(If &if_node)
{
  bool result = false;
  for (Statement *stmt : if_node.if_block->stmts) {
    if (visit(stmt))
      result = true;
  }
  if (!result) {
    // if block has no return
    return false;
  }

  for (Statement *stmt : if_node.else_block->stmts) {
    if (visit(stmt)) {
      // both blocks have a return
      return true;
    }
  }
  // else block has no return (or there is no else block)
  return false;
}

Pass CreateReturnPathPass(std::ostream &out)
{
  return Pass("ReturnPath", [&out](PassContext &ctx) {
    auto return_path = ReturnPathAnalyser();
    if (!return_path.visit(ctx.ast_ctx.root)) {
      out << return_path.error();
      return PassResult::Error("ReturnPath", 1);
    }
    return PassResult::Success();
  });
}

} // namespace bpftrace::ast
