#include "return_path_analyser.h"
#include "log.h"

namespace bpftrace::ast {

ReturnPathAnalyser::ReturnPathAnalyser(Program &program, std::ostream &out)
    : program_(program), out_(out)
{
}

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

  for (StatementVariant stmt : subprog.stmts) {
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
  for (StatementVariant stmt : if_node.if_block->stmts) {
    if (visit(stmt))
      result = true;
  }
  if (!result) {
    // if block has no return
    return false;
  }

  for (StatementVariant stmt : if_node.else_block->stmts) {
    if (visit(stmt)) {
      // both blocks have a return
      return true;
    }
  }
  // else block has no return (or there is no else block)
  return false;
}

int ReturnPathAnalyser::analyse()
{
  int result = visitAll(program_) ? 0 : 1;
  if (result)
    out_ << err_.str();
  return result;
}

Pass CreateReturnPathPass()
{
  auto fn = [](Program &program, __attribute__((unused)) PassContext &ctx) {
    auto return_path = ReturnPathAnalyser(program);
    int err = return_path.analyse();
    if (err)
      return PassResult::Error("ReturnPath");
    return PassResult::Success();
  };

  return Pass("ReturnPath", fn);
}

} // namespace bpftrace::ast
