#include <sstream>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/external_types.h"
#include "ast/passes/printer.h"
#include "ast/passes/type_system.h"
#include "ast/visitor.h"
#include "driver.h"

namespace bpftrace::ast {

namespace {
class CastResolver : public Visitor<CastResolver> {
public:
  CastResolver(ASTContext &ast, TypeMetadata &types)
      : ast_(ast), types_(types) {};

  using Visitor<CastResolver>::visit;

  void visit(Expression &expr)
  {
    Visitor<CastResolver>::visit(expr);
    if (auto *cast_or_binop = expr.as<CastOrBinop>()) {
      if (std::holds_alternative<TypeSpec>(cast_or_binop->lhs)) {
        // Convert to a cast and unary operation.
        auto *unop = ast_.make_node<Unop>(cast_or_binop->loc,
                                          cast_or_binop->op,
                                          cast_or_binop->rhs);
        expr.value = ast_.make_node<Cast>(
            cast_or_binop->loc, std::get<TypeSpec>(cast_or_binop->lhs), unop);
      } else {
        // Convert to a binary expression.
        expr.value = ast_.make_node<Binop>(cast_or_binop->loc,
                                           cast_or_binop->op,
                                           cast_or_binop->lhs,
                                           cast_or_binop->rhs);
      }
    }
  }

  void visit(std::variant<Expression, TypeSpec> &ambiguous)
  {
    if (std::holds_alternative<Expression>(ambiguous)) {
      auto &expr = std::get<Expression>(ambiguous);
      // Attempt to resolve the printed expression as a type. If it
      // resolves correctly, then this is a *cast*.
      //
      // First, we need to convert the expression to a naked string.
      std::stringstream ss;
      MetadataIndex metadata;
      ss << Formatter(FormatMode::Minimal, metadata, 120).visit(expr);
      // Next, we attempt to parse this as a type. This uses the
      // original ASTContext because we may preserve these nodes.
      Driver driver(ast_);
      auto type_spec = driver.parse_type();
      if (type_spec) {
        auto sized_type = type_spec->resolve(types_.global);
        if (!sized_type.IsNoneTy()) {
          ambiguous = std::move(*type_spec);
        }
      }
    }
  }

private:
  ASTContext &ast_;
  TypeMetadata &types_;
};

} // namespace

ast::Pass CreateDefineExternalTypesPass()
{
  return ast::Pass::create("ExternalTypes",
                           [](ASTContext &ast, TypeMetadata &types) {
                             CastResolver(ast, types).visit(ast.root);
                           });
}

} // namespace bpftrace::ast
