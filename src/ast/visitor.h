#pragma once

#include <optional>
#include <variant>

#include "ast/ast.h"

namespace bpftrace::ast {

// Visitor for fully-static visitation.
//
// This uses CRTP to make all calls static, while still allowing the entrypoint
// for a single visitor to be dispatched dynamically. The implementation may
// optionally provide individual `visit` methods (matching references, which
// can be rewritten).
template <typename Impl, typename R = void>
class Visitor {
public:
  // visit methods are used to traverse the graph, and are provided a reference
  // to the underlying node. The visit is invoked *before* the replace call,
  // and can directly consume and modify the results of the visit.
  R visit([[maybe_unused]] Integer &integer)
  {
    return default_value();
  }
  R visit([[maybe_unused]] PositionalParameter &integer)
  {
    return default_value();
  }
  R visit([[maybe_unused]] String &string)
  {
    return default_value();
  }
  R visit([[maybe_unused]] Builtin &builtin)
  {
    return default_value();
  }
  R visit([[maybe_unused]] Identifier &identifier)
  {
    return default_value();
  }
  R visit([[maybe_unused]] StackMode &mode)
  {
    return default_value();
  }
  R visit([[maybe_unused]] Variable &var)
  {
    return default_value();
  }
  R visit([[maybe_unused]] SubprogArg &subprog_arg)
  {
    return default_value();
  }
  R visit([[maybe_unused]] AttachPoint &ap)
  {
    return default_value();
  }
  R visit(Call &call)
  {
    return visitImpl(call.vargs);
  }
  R visit(Sizeof &szof)
  {
    // See `SizedType` below.
    return visitImpl(szof.expr);
  }
  R visit(Offsetof &ofof)
  {
    // See `SizedType` below.
    return visitImpl(ofof.expr);
  }
  R visit([[maybe_unused]] MapDecl &decl)
  {
    return default_value();
  }
  R visit(Map &map)
  {
    return visitImpl(map.key_expr);
  }
  R visit(Binop &binop)
  {
    visitImpl(binop.left);
    visitImpl(binop.right);
    return default_value();
  }
  R visit(Unop &unop)
  {
    return visitImpl(unop.expr);
  }
  R visit(Ternary &ternary)
  {
    visitImpl(ternary.cond);
    visitImpl(ternary.left);
    visitImpl(ternary.right);
    return default_value();
  }
  R visit(FieldAccess &acc)
  {
    return visitImpl(acc.expr);
  }
  R visit(ArrayAccess &arr)
  {
    visitImpl(arr.expr);
    visitImpl(arr.indexpr);
    return default_value();
  }
  R visit(TupleAccess &acc)
  {
    return visitImpl(acc.expr);
  }
  R visit(Cast &cast)
  {
    return visitImpl(cast.expr);
  }
  R visit(Tuple &tuple)
  {
    return visitImpl(tuple.elems);
  }
  R visit(ExprStatement &expr)
  {
    return visitImpl(expr.expr);
  }
  R visit(AssignMapStatement &assignment)
  {
    visitImpl(assignment.map);
    visitImpl(assignment.expr);
    return default_value();
  }
  R visit(AssignVarStatement &assignment)
  {
    visitImpl(assignment.var);
    visitImpl(assignment.expr);
    return default_value();
  }
  R visit(AssignConfigVarStatement &assignment)
  {
    return visitImpl(assignment.expr);
  }
  R visit(VarDeclStatement &decl)
  {
    return visitImpl(decl.var);
  }
  R visit(If &if_node)
  {
    visitImpl(if_node.cond);
    visitImpl(if_node.if_block);
    visitImpl(if_node.else_block);
    return default_value();
  }
  R visit(Jump &jump)
  {
    return visitImpl(jump.return_value);
  }
  R visit(Unroll &unroll)
  {
    visitImpl(unroll.expr);
    visitImpl(unroll.block);
    return default_value();
  }
  R visit(While &while_block)
  {
    visitImpl(while_block.cond);
    visitImpl(while_block.block);
    return default_value();
  }
  R visit(For &for_loop)
  {
    visitImpl(for_loop.decl);
    visitImpl(for_loop.expr);
    visitImpl(for_loop.stmts);
    return default_value();
  }
  R visit(Predicate &pred)
  {
    return visitImpl(pred.expr);
  }
  R visit(Probe &probe)
  {
    visitImpl(probe.attach_points);
    visitImpl(probe.pred);
    visitImpl(probe.block);
    return default_value();
  }
  R visit(Config &config)
  {
    visitImpl(config.stmts);
    return default_value();
  }
  R visit(Block &block)
  {
    visitImpl(block.stmts);
    visitImpl(block.expr);
    return default_value();
  }
  R visit(Subprog &subprog)
  {
    visitImpl(subprog.args);
    visitImpl(subprog.stmts);
    return default_value();
  }
  R visit(Program &program)
  {
    // This order is important
    visitImpl(program.config);
    visitImpl(program.functions);
    visitImpl(program.map_decls);
    visitImpl(program.probes);
    return default_value();
  }
  R visit(Expression &expr)
  {
    return std::visit([&](auto &v) { return visitImpl(v); }, expr.value());
  }
  R visit(Statement &stmt)
  {
    return std::visit([&](auto &v) { return visitImpl(v); }, stmt.value());
  }

  // Automatically unpack and dispatch all variant and vector types into the
  // suitable visitor method.
  //
  // In order to automatically replace a variant, e.g. change from type A to
  // type B, it is necessary to provide a replace method that accepts that
  // variant type directly. This could still dispatch via the standard visit
  // function, which could e.g. return the replacement pointer, but this would
  // be a single specialized pass for this case.
  template <typename... Ts>
  R visit(std::variant<Ts...> &var)
  {
    return std::visit([&](auto &value) -> R { return visitImpl(value); }, var);
  }
  template <typename T>
  R visit(std::optional<T> &var)
  {
    if (var) {
      return visitImpl(var.value());
    }
    return default_value();
  }
  template <typename T>
  R visit(std::reference_wrapper<T> ref)
  {
    return visitImpl(ref.get());
  }
  template <typename T>
  R visit(std::vector<T> &vec)
  {
    for (auto &v : vec) {
      visit(v);
    }
    return default_value();
  }
  R visit([[maybe_unused]] std::monostate &var)
  {
    return default_value();
  }
  R visit([[maybe_unused]] SizedType &var)
  {
    // Some nodes contain variants over expressions and types (`Offsetof` and
    // `Sizeof`). For simplicity, simply allow these visits and ignore them.
    return default_value();
  }

private:
  template <typename T>
  R visitImpl(T &t)
  {
    Impl *impl = static_cast<Impl *>(this);
    impl->visit(t);
  }
  R default_value()
  {
    if constexpr (!std::is_void_v<R>) {
      return R();
    }
  }
};

} // namespace bpftrace::ast
