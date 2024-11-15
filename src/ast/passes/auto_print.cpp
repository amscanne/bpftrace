#include "portability_analyser.h"

#include <cstdlib>

#include "log.h"
#include "types.h"

namespace bpftrace::ast {

AutoPrintAnalyser::AutoPrintAnalyser(ASTContext &ctx) : ctx_(ctx)
{
}

void AutoPrintAnalyser::visit(ExprStatement &statement)
{
  // If this statement is a bare identifier, without any side-effects, then
  // automatically promote into a print statement. Note that this was
  // previously guarranteed to be optimized away during compilation, so it is
  // unlikely that any programs existed with a vestigal identifier statement.
  auto ident = dynamic_cast<Identifier*>(statement.expr);
  if (ident) {
    statement.expr = ctx_.make_node<ast::Call>("print", ExpressionList{ident});
  }
  Visitor::visit(statement);
}

Pass CreateAutoPrintPass()
{
  auto fn = [](Node &n, PassContext &__attribute__((unused))) {
    AutoPrintAnalyser analyser;
    analyser.Visit(*root_);
    return PassResult::Success();
  };

  return Pass("AutoPrintAnalyser", fn);
}

} // namespace bpftrace::ast
