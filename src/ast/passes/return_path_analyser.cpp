#include "ast/passes/return_path_analyser.h"
#include "ast/ast.h"
#include "ast/context.h"
#include "ast/visitor.h"
#include "util/type_name.h"

namespace bpftrace::ast {

namespace {

class ExitReturn : public Visitor<ExitReturn> {
public:
  ExitReturn(ASTContext &ast) : ast_(ast) {};
  using Visitor<ExitReturn>::visit;
  void visit(Expression &expr);

private:
  ASTContext &ast_;
};

template <util::TypeName name, JumpType... Ts>
class JumpDisallowed : public Visitor<JumpDisallowed<name, Ts...>> {
public:
  using Visitor<JumpDisallowed>::visit;
  void visit([[maybe_unused]] Subprog &subprog)
  {
    JumpDisallowed<"function", JumpType::BREAK, JumpType::CONTINUE>().visit(
        subprog.block);
  }
  void visit([[maybe_unused]] For &f)
  {
    JumpDisallowed<"for-loop", JumpType::RETURN>().visit(f.block);
  }
  void visit([[maybe_unused]] While &w)
  {
    JumpDisallowed<"while-loop", JumpType::RETURN>().visit(w.block);
  }
  void visit(Macro &macro)
  {
    JumpDisallowed<"macro",
                   JumpType::BREAK,
                   JumpType::CONTINUE,
                   JumpType::RETURN>()
        .visit(macro.block);
  }
  void visit(Probe &p)
  {
    JumpDisallowed<"probe", JumpType::BREAK, JumpType::CONTINUE>().visit(
        p.block);
  }
  void visit(Jump &jump)
  {
    if (((jump.ident == Ts) || ...))
      jump.addError() << "'" << opstr(jump) << "' "
                      << "statement is not allowed in a " << name.str();
  }
};

template <JumpType... Ts>
class ReturnPathAnalyser : public Visitor<ReturnPathAnalyser<Ts...>, bool> {
public:
  // visit methods return true iff all return paths of the analyzed code
  // (represented by the given node) return a value.
  using Visitor<ReturnPathAnalyser, bool>::visit;
  bool visit(Jump &jump)
  {
    return ((jump.ident == Ts) || ...);
  }
  bool visit(IfExpr &if_expr)
  {
    return visit(if_expr.left) && visit(if_expr.right);
  }
  bool visit(BlockExpr &block)
  {
    for (size_t i = 0; i < block.stmts.size(); i++) {
      if (visit(block.stmts[i])) {
        // Leave an error on any unreachable code.
        if (i + 1 < block.stmts.size()) {
          block.stmts[i + 1].node().addError() << "Unreachable statement.";
        }
        // If there is a non-none expression, then it is not possible
        // to evaluate this expression. This is also an error.
        if (!block.expr.is<None>()) {
          block.expr.node().addError() << "Unreachable expression.";
        }
        return true;
      }
    }
    return visit(block.expr);
  }
  bool visit([[maybe_unused]] Subprog &subprog)
  {
    // In case we ever allow nested subprograms, these are explicitly
    // scope-limited, so neither jump affects overall control flow.
    return false;
  }
  bool visit([[maybe_unused]] For &f)
  {
    // Scope limit break/return to loops.
    return false;
  }
  bool visit([[maybe_unused]] While &w)
  {
    // See above.
    return false;
  }
};

class ReturnAnalyser : public Visitor<ReturnAnalyser> {
public:
  explicit ReturnAnalyser(ASTContext &ast) : ast_(ast) {};

  using Visitor<ReturnAnalyser>::visit;
  void visit(Subprog &subprog);
  void visit(Probe &probe);
  void visit(Macro &macro);
  void visit(For &f);
  void visit(While &w);

private:
  ASTContext &ast_;
};

} // namespace

template <JumpType T>
void inject_jump(ASTContext &ast, Expression &expr)
{
  if (auto *blockexpr = expr.as<BlockExpr>()) {
    inject_jump<T>(ast, *blockexpr);
  } else if (auto *if_expr = expr.as<IfExpr>()) {
    // Because ifs may be folded in the future, we need to inject into
    // both if one of the branches has the terminator. It is also possible
    // that one of the branches also has it, so we don't inject there.
    ReturnPathAnalyser<T> checker;
    if (!checker.visit(if_expr->left)) {
      inject_jump<T>(ast, if_expr->left);
    }
    if (!checker.visit(if_expr->right)) {
      inject_jump<T>(ast, if_expr->right);
    }
  } else {
    // Inject a jump by converting to a block expression.
    auto *stmt = ast.make_node<ExprStatement>(expr, Location(expr.node().loc));
    auto *ret = ast.make_node<Jump>(T, Location(expr.node().loc));
    auto *none = ast.make_node<None>(Location(expr.node().loc));
    auto *block = ast.make_node<BlockExpr>(StatementList({ stmt, ret }),
                                           none,
                                           Location(expr.node().loc));
    expr.value = block;
  }
}

template <JumpType T>
void inject_jump(ASTContext &ast, BlockExpr &block)
{
  auto *jump = ast.make_node<Jump>(T, Location(block.loc));
  if (block.expr.is<None>()) {
    // Check the final statement. If this statement is itself a block or
    // if expression, then we recursively inject a jump into that block.
    // This is done before those branches may be pruned, and we might end
    // up with a `return; return;` in that case.
    if (!block.stmts.empty() && block.stmts.back().is<ExprStatement>()) {
      inject_jump<T>(ast, block.stmts.back().as<ExprStatement>()->expr);
    } else {
      block.stmts.emplace_back(jump);
    }
  } else {
    inject_jump<T>(ast, block.expr);
  }
}

void ExitReturn::visit(Expression &expr)
{
  Visitor<ExitReturn>::visit(expr);

  // The `exit` call is special and always carries an implicit return following
  // the call. We inject it automatically. Anything following this will be
  // labelled as unreachable as per the regular error paths below.
  //
  // This also prevents `exit` from appearing anywhere that a naked return is
  // not allowed (e.g. a macro, etc.) which is a useful feature.
  if (auto *call = expr.as<Call>()) {
    if (call->func == "exit" && call->vargs.size() <= 1) {
      inject_jump<JumpType::RETURN>(ast_, expr);
    }
  }
}

void ReturnAnalyser::visit(Subprog &subprog)
{
  bool has_return = ReturnPathAnalyser<JumpType::RETURN>().visit(subprog.block);
  if (!has_return) {
    if (subprog.return_type->type().IsVoidTy()) {
      inject_jump<JumpType::RETURN>(ast_, *subprog.block);
    } else {
      subprog.addError() << "Not all code paths returned a value";
    }
  }

  // Recurse to check loops, etc.
  visit(subprog.block);
}

void ReturnAnalyser::visit(Probe &probe)
{
  // Ensure that we have an implicit return for the probe.
  if (!ReturnPathAnalyser<JumpType::RETURN>().visit(probe.block)) {
    inject_jump<JumpType::RETURN>(ast_, *probe.block);
  }

  // Check all loops, etc.
  visit(probe.block);
}

void ReturnAnalyser::visit(Macro &macro)
{
  // Macros are already verified not to contain any control flow directly, but
  // may contain embedded loops, etc. These need to be fixed up to ensure that
  // every block ends with a control flow statement.
  visit(macro.block);
}

void ReturnAnalyser::visit(For &f)
{
  // Visit the loop and record any errors wherein we have
  // unreachable statements due to a unilateral break/continue.
  if (!ReturnPathAnalyser<JumpType::BREAK, JumpType::CONTINUE>().visit(
          f.block)) {
    inject_jump<JumpType::CONTINUE>(ast_, *f.block);
  }

  // Recurse to check nested loops, etc.
  visit(f.block);
}

void ReturnAnalyser::visit(While &w)
{
  // Same as for while loops.
  if (!ReturnPathAnalyser<JumpType::BREAK, JumpType::CONTINUE>().visit(
          w.block)) {
    inject_jump<JumpType::CONTINUE>(ast_, *w.block);
  }

  visit(w.block);
}

Pass CreateReturnPathPass()
{
  auto fn = [](ASTContext &ast) {
    ExitReturn(ast).visit(ast.root);
    JumpDisallowed<"program">().visit(ast.root);
    ReturnAnalyser r(ast);
    r.visit(ast.root);
    return ReturnPathsChecked();
  };

  return Pass::create("ReturnPath", fn);
}

} // namespace bpftrace::ast
