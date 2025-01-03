#include "field_analyser.h"

#include <cassert>
#include <iostream>

#include "arch/arch.h"
#include "dwarf_parser.h"
#include "log.h"
#include "probe_matcher.h"

namespace bpftrace::ast {

void FoldConstants::simplify(Expression **expr)
{
  if (*expr == nullptr)
    return; // No expression.

  // Process the expression.
  (*expr)->accept(this);

  // If after processing this expression, we found that there has been a
  // "simplified" expression pushed to the stack, then we replace this
  // expression with that one.
  if (simplified_) {
    *expr = simplified_;
    simplified_ = nullptr;
  }
}

void FoldConstants::reduce(Expression *expr)
{
  // This is consumed by `simplify` above.
  assert(simplified_ == nullptr);
  simplified_ =  expr;
}

void FoldConstants::visit(Builtin &builtin)
{
  Visit::visit(builtin);
  // For now, we are not folding any builtins. But note that this may prevent
  // certain optimizations, such as combination with other operations, etc.
  // This can be done as a follow-up.
}

void FoldConstants::visit(Call &call)
{
  // If this is a call to `str` with a single argument, then we can generally
  // just converted this immediately.
  if (call.func == "str" && call.vargs.size() == 1) {
    auto arg = call.vargs.at(0);
    if (auto str = dynamic_cast<String*>(arg)) {
    } else (auto pos = dynamic_cast<PositionalParameter*>(arg)) {
      return reduce(ctx_.make_node<String>(bpftrace_.get_param(pos->n, true)));
    } else (auto in = dynamic_cast<Integer*>(arg)) {
      return reduce(ctx_.make_node<String>(std::to_string(in->n)));
    }
  }

  // Otherwise, just fold all the arguments.
  for (auto &expr : call.vargs) {
    simplify(&expr);
  }
}

void FoldConstants::visit(Sizeof &szof)
{
  simplify(&szof.expr);
}

void FoldConstants::visit(Offsetof &ofof)
{
  simplify(&ofof.expr);
}

void FoldConstants::visit(Map &map)
{
  simplify(&var.key_expr);
}

void FoldConstants::visit(Variable &var)
{
  simplify(&var.expr);
}

void FoldConstants::visit(Binop &binop)
{
  simplify(&binop.left);
  simplify(&binop.right);

  // We can fold binary operations in the result, if both sides are constant.
  if ((auto left = dynamic_cast<String*>(binop.left)) && (auto right = dynamic_cast<String*>(binop.right))) {
    switch (binop.op) {
    case Operator::EQ:
    case Operator::NE:
    }
  } else if ((auto left = dynamic_cast<Integer*>(binop.left)) && (auto right = dynamic_cast<Integer*>(binop.right))) {
    switch (binop.op) {
    case Operator::EQ:
      return ctx_.make_node<Integer>(left->n == right->n, bin.loc);
    }
  } else if ((auto left = dynamic_cast<String*>(binop.left)) && (auto right = dynamic_cast<Integer*>(binop.right))) {
    switch (binop.op) {
    case Operator::PLUS:
    default:
      // XXX LOG(ERROR) << "Illegal operation on string and integer: ";
    }
  }
}

void FoldConstants::visit(Unop &unop)
{
  simplify(&unop.expr);
}

void FoldConstants::visit(Ternary &ternary)
{
  simplify(&tenary.cond);
  simplify(&tenary.left);
  simplify(&tenary.right);
}

void FoldConstants::visit(FieldAccess &acc)
{
  Visit::visit(acc);
  simplify(&acc.expr);
}

void FoldConstants::visit(ArrayAccess &arr)
{
  Visit::visit(arr);
  simplify(&arr.expr);
  simplify(&arr.inexpr);
}

void FoldConstants::visit(Cast &cast)
{
  simplify(&cast.expr);
}

void FoldConstants::visit(Tuple &tuple)
{
  for (auto &expr : tuple.elems) {
    simplify(&expr);
  }
}

void FoldConstants::visit(ExprStatement &expr)
{
  simplify(&expr.expr);
}

void FoldConstants::visit(AssignMapStatement &assignment)
{
  simplify(&assignment.expr);
}

void FoldConstants::visit(AssignVarStatement &assignment)
{
  simplify(&assignment.expr);
}

void FoldConstants::visit(AssignConfigVarStatement &assignment)
{
  simplify(&assignment.expr);
}

void FoldConstants::visit(VarDeclStatement &decl)
{
  simplify(&decl.expr);
}

void FoldConstants::visit(If &if_node)
{
  simplify(&if_node.cond);
  Visit(if_node.block);
}

void FoldConstants::visit(Unroll &unroll)
{
  simplify(&unroll.expr);
  Visit(unroll.block);
}

void FoldConstants::visit(While &while_block)
{
  simplify(&while_block.cond);
  Visit(while_block.block);
}

void FoldConstants::visit(For &for_loop)
{
  simplify(&for_loop.cond);
  Visit(for_loop.block);
}

void FoldConstants::visit(Predicate &pred)
{
  simplify(&pred.expr);
}

std::optional<int64_t> BPFtrace::get_int_literal(
    const ast::Expression *expr) const
{
  if (auto *integer = dynamic_cast<const ast::Integer *>(expr)) {
    return integer->n;
  } else if (auto *pos_param = dynamic_cast<const ast::PositionalParameter *>(
                 expr)) { 
    auto param_str = get_param(pos_param->n, false);
    auto param_int = get_int_from_str(param_str);
    if (!param_int.has_value()) {
      LOG(ERROR, pos_param->loc)
         << "$" << pos_param->n << " used numerically but given \""
         << param_str << "\"";
      return std::nullopt;
    }
    if (std::holds_alternative<int64_t>(*param_int)) {
      return std::get<int64_t>(*param_int);
    } else { 
      return static_cast<int64_t>(std::get<uint64_t>(*param_int));
    }
  } else if (auto *pos_count = dynamic_cast<const ast::CountParameter *>(expr)) {
    return static_cast<int64_t>(num_params());
  }
    
  return std::nullopt;
}

std::optional<std::string> BPFtrace::get_string_literal(const ast::Expression *expr) const
{
  if (auto *string = dynamic_cast<const ast::String *>(expr))
    return string->str;
  else if (auto *str_call = dynamic_cast<const ast::Call *>(expr)) {
    // Positional parameters in the form str($1) can be used as literals
    if (str_call->func == "str") {
      if (auto *pos_param = dynamic_cast<const ast::PositionalParameter *>(
              str_call->vargs.at(0)))
        return get_param(pos_param->n, true);
    }
  }
  
  LOG(ERROR) << "Expected string literal, got " << expr->type;
  return "";


} // namespace bpftrace::ast
