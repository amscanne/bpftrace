#include "ast/ast.h"
#include "ast/context.h"

namespace bpftrace::ast {

Diagnostic &Node::addError() const
{
  return state_.diagnostics_->addError(loc);
}

Diagnostic &Node::addWarning() const
{
  return state_.diagnostics_->addWarning(loc);
}

const SizedType &Expression::type() const
{
  return std::visit(
      [](const auto *expr) -> const SizedType & { return expr->type(); },
      value);
}

bool Expression::is_literal() const
{
  if (is<Integer>() || is<NegativeInteger>() || is<String>() || is<Boolean>()) {
    return true;
  }
  if (auto *tuple = as<Tuple>()) {
    return std::ranges::all_of(tuple->elems, [](const auto &elem) {
      return elem.is_literal();
    });
  }
  return false;
}

static constexpr std::string_view ENUM = "enum ";

std::string opstr(const Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      return "return";
    case JumpType::BREAK:
      return "break";
    case JumpType::CONTINUE:
      return "continue";
    default:
      return {};
  }

  return {}; // unreached
}

std::string opstr(const Binop &binop)
{
  switch (binop.op) {
    case Operator::EQ:
      return "==";
    case Operator::NE:
      return "!=";
    case Operator::LE:
      return "<=";
    case Operator::GE:
      return ">=";
    case Operator::LT:
      return "<";
    case Operator::GT:
      return ">";
    case Operator::LAND:
      return "&&";
    case Operator::LOR:
      return "||";
    case Operator::LEFT:
      return "<<";
    case Operator::RIGHT:
      return ">>";
    case Operator::PLUS:
      return "+";
    case Operator::MINUS:
      return "-";
    case Operator::MUL:
      return "*";
    case Operator::DIV:
      return "/";
    case Operator::MOD:
      return "%";
    case Operator::BAND:
      return "&";
    case Operator::BOR:
      return "|";
    case Operator::BXOR:
      return "^";
    default:
      return {};
  }

  return {}; // unreached
}

std::string opstr(const Unop &unop)
{
  switch (unop.op) {
    case Operator::LNOT:
      return "!";
    case Operator::BNOT:
      return "~";
    case Operator::MINUS:
      return "-";
    case Operator::MUL:
      return "dereference";
    case Operator::INCREMENT:
      if (unop.is_post_op)
        return "++ (post)";
      return "++ (pre)";
    case Operator::DECREMENT:
      if (unop.is_post_op)
        return "-- (post)";
      return "-- (pre)";
    default:
      return {};
  }

  return {}; // unreached
}

bool is_comparison_op(Operator op)
{
  switch (op) {
    case Operator::EQ:
    case Operator::NE:
    case Operator::LE:
    case Operator::GE:
    case Operator::LT:
    case Operator::GT:
    case Operator::LAND:
    case Operator::LOR:
      return true;
    case Operator::PLUS:
    case Operator::MINUS:
    case Operator::MUL:
    case Operator::DIV:
    case Operator::MOD:
    case Operator::BAND:
    case Operator::BOR:
    case Operator::BXOR:
    case Operator::LEFT:
    case Operator::RIGHT:
    case Operator::ASSIGN:
    case Operator::INCREMENT:
    case Operator::DECREMENT:
    case Operator::LNOT:
    case Operator::BNOT:
      return false;
  }

  return false; // unreached
}

SizedType ident_to_record(const std::string &ident, int pointer_level)
{
  SizedType result = CreateRecord(ident);
  for (int i = 0; i < pointer_level; i++)
    result = CreatePointer(result);
  return result;
}

SizedType ident_to_sized_type(const std::string &ident)
{
  if (ident.starts_with(ENUM)) {
    auto enum_name = ident.substr(ENUM.size());
    // This is an automatic promotion to a uint64
    // even though it's possible that highest variant value of that enum
    // fits into a smaller int. This will also affect casts from a smaller
    // int and cause an ERROR: Integer size mismatch.
    // This could potentially be revisited or the cast relaxed
    // if we check the variant values during semantic analysis.
    return CreateEnum(64, enum_name);
  }
  return ident_to_record(ident);
}

} // namespace bpftrace::ast
