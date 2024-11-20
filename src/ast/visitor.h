#pragma once

#include <string>

#include "ast/ast.h"

namespace bpftrace::ast {

// Visitor for fully-static visitation.
//
// This uses CRTP to make all calls static, while still allowing the entrypoint
// for a single visitor to be dispatched dynamically. The implementation may
// optionally provide individual `visit` methods (matching either pointers or
// references, the latter preferred), or `replace` methods (matching just the
// relevant pointer types and returning the same) which can return new nodes
// when replacement is required. This makes it simple to write self-contained
// passes that rewrite part of the AST.
//
// Note that replacement is not currently possible for aggregate types (e.g.
// std::vector), and these will still be visited (and possible replaced on an
// item-side basis). If modification of these is needed, then the visitor
// should do replacement inline within the owner of the list, i.e. replace the
// full Block node, rather than attempting to intersect the list.
template <typename Impl, typename R = void>
class Visitor {
public:
  Visitor(ASTContext &ctx) : ctx_(ctx)
  {
  }

  // See above; specific replace methods may be defined.
  template <typename T>
  T *replace(T *node, [[maybe_unused]] R *result)
  {
    return node;
  }

  // visit methods are used to traverse the graph, and are provided a reference
  // to the underlying node. The visit is invoked *before* the replace call,
  // and can directly consume and modify the results of the visit.
  R visit(Integer &integer __attribute__((__unused__)))
  {
    return default_value();
  }
  R visit(PositionalParameter &integer __attribute__((__unused__)))
  {
    return default_value();
  }
  R visit(String &string __attribute__((__unused__)))
  {
    return default_value();
  }
  R visit(Builtin &builtin __attribute__((__unused__)))
  {
    return default_value();
  }
  R visit(Identifier &identifier __attribute__((__unused__)))
  {
    return default_value();
  }
  R visit(StackMode &mode __attribute__((__unused__)))
  {
    return default_value();
  }
  R visit(Variable &var __attribute__((__unused__)))
  {
    return default_value();
  }
  R visit(SubprogArg &subprog_arg __attribute__((__unused__)))
  {
    return default_value();
  }
  R visit(AttachPoint &ap __attribute__((__unused__)))
  {
    return default_value();
  }
  R visit(Call &call)
  {
    return visitImpl(call.vargs);
  }
  R visit(Sizeof &szof)
  {
    return visitModify(&szof.expr);
  }
  R visit(Offsetof &ofof)
  {
    return visitModify(&ofof.expr);
  }
  R visit(Map &map)
  {
    return visitModify(&map.key_expr);
  }
  R visit(Binop &binop)
  {
    visitModify(&binop.left);
    visitModify(&binop.right);
    return default_value();
  }
  R visit(Unop &unop)
  {
    return visitModify(&unop.expr);
  }
  R visit(Ternary &ternary)
  {
    visitModify(&ternary.cond);
    visitModify(&ternary.left);
    visitModify(&ternary.right);
    return default_value();
  }
  R visit(FieldAccess &acc)
  {
    return visitModify(&acc.expr);
  }
  R visit(ArrayAccess &arr)
  {
    visitModify(&arr.expr);
    visitModify(&arr.indexpr);
    return default_value();
  }
  R visit(Cast &cast)
  {
    return visitModify(&cast.expr);
  }
  R visit(Tuple &tuple)
  {
    return visitImpl(tuple.elems);
  }
  R visit(ExprStatement &expr)
  {
    return visitModify(&expr.expr);
  }
  R visit(AssignMapStatement &assignment)
  {
    visitModify(&assignment.map);
    visitModify(&assignment.expr);
    return default_value();
  }
  R visit(AssignVarStatement &assignment)
  {
    visitModify(&assignment.var);
    visitModify(&assignment.expr);
    return default_value();
  }
  R visit(AssignConfigVarStatement &assignment)
  {
    return visitModify(&assignment.expr);
  }
  R visit(VarDeclStatement &decl)
  {
    return visitModify(&decl.var);
  }
  R visit(If &if_node)
  {
    visitModify(&if_node.cond);
    visitModify(&if_node.if_block);
    visitModify(&if_node.else_block);
    return default_value();
  }
  R visit(Jump &jump)
  {
    return visitModify(&jump.return_value);
  }
  R visit(Unroll &unroll)
  {
    visitModify(&unroll.expr);
    visitModify(&unroll.block);
    return default_value();
  }
  R visit(While &while_block)
  {
    visitModify(&while_block.cond);
    visitModify(&while_block.block);
    return default_value();
  }
  R visit(For &for_loop)
  {
    visitModify(&for_loop.decl);
    visitModify(&for_loop.expr);
    visitImpl(for_loop.stmts);
    return default_value();
  }
  R visit(Predicate &pred)
  {
    return visitModify(&pred.expr);
  }
  R visit(Probe &probe)
  {
    visitImpl(probe.attach_points);
    visitModify(&probe.pred);
    visitModify(&probe.block);
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
    visitImpl(program.functions);
    visitImpl(program.probes);
    visitModify(&program.config);
    return default_value();
  }

  // Temporarily allow visits to expression and statement references. This
  // does not permit the modification of the underlying value, but does allow
  // the existing passes to continue to work (which do not modify anything, so
  // this is not a problem for the time being).
  template <typename T>
  R visit(T &t)
  {
    auto ptr = &t;
    if constexpr (!std::is_void_v<R>) {
      auto rval = visitModify(&ptr);
      assert(ptr == &t); // Should not be modified.
      return rval;
    } else {
      visitModify(&ptr);
      assert(ptr == &t); // See above.
    }
  }

  // Automatically unpacked and dispatch all variant and vector types into the
  // suitable visitor method.
  //
  // In order to automatically replace a variant, e.g. change from type A to
  // type B, it is necessary to provide a replace method that accepts that
  // variant type directly. This could still dispatch via the standard visit
  // function, which could e.g. return the replacement pointer, but this would
  // be a single specialized pass for this case.
  template <typename... Ts>
  R visit(std::variant<Ts *...> var)
  {
    return std::visit([this](auto &value) -> R { return visitModify(&value); },
                      var);
  }
  template <typename T>
  R visit(std::vector<T *> &var)
  {
    for (auto &value : var) {
      visitModify(&value);
    }
    return default_value();
  }
  template <typename T>
  R visit(std::optional<T *> &var)
  {
    if (var) {
      return visitModify(&(*var));
    }
    return default_value();
  }

  // This is a convenience for dispatching directly from a pointer type, it
  // does not allow for replacement of this specific instance.
  template <typename T>
  R visit(T *ptr)
  {
    if (ptr)
      return visitImpl(*ptr);
    return default_value();
  }

private:
  template <typename T>
  R visitImpl(T &t)
  {
    Impl *impl = static_cast<Impl *>(this);
    return impl->visit(t);
  }
  template <typename T>
  R visitModify(T **t)
  {
    auto orig = *t; // Prior to replacement.
    Impl *impl = static_cast<Impl *>(this);
    if constexpr (!std::is_void_v<R>) {
      auto rval = impl->visit(orig);
      *t = impl->replace(orig, &rval);
      return rval;
    } else {
      impl->visit(orig);
      *t = impl->replace(orig, nullptr);
      return default_value();
    }
  }
  R default_value()
  {
    if constexpr (!std::is_void_v<R>) {
      return R();
    }
  }

  // These are the runtime-type adaptors that are currently required for
  // Expression and Statement, but can be removed by encoding this type
  // information into the AST directly.
  template <typename Orig, typename T, typename... Ts>
  R tryVisitModify(Orig **node)
  {
    if (auto *t = dynamic_cast<T>(*node)) {
      if constexpr (!std::is_void_v<R>) {
        auto rval = visitModify(&t);
        *node = static_cast<Orig *>(t); // Copy the modification.
        return rval;
      } else {
        visitModify(&t);
        *node = static_cast<Orig *>(t); // See above.
        return;
      }
    } else if constexpr (sizeof...(Ts) != 0) {
      return tryVisitModify<Orig, Ts...>(node);
    }
    return default_value();
  }
  R visitModify(Expression **expr)
  {
    return tryVisitModify<Expression,
                          Integer *,
                          PositionalParameter *,
                          String *,
                          StackMode *,
                          Identifier *,
                          Builtin *,
                          Call *,
                          Sizeof *,
                          Offsetof *,
                          Map *,
                          Variable *,
                          Binop *,
                          Unop *,
                          FieldAccess *,
                          ArrayAccess *,
                          Cast *,
                          Tuple *,
                          Ternary *>(expr);
  }
  R visitModify(Statement **stmt)
  {
    return tryVisitModify<Statement,
                          ExprStatement *,
                          VarDeclStatement *,
                          AssignMapStatement *,
                          AssignVarStatement *,
                          AssignConfigVarStatement *,
                          Block *,
                          If *,
                          Unroll *,
                          Jump *,
                          While *,
                          For *,
                          Config *>(stmt);
  }

protected:
  ASTContext &ctx_;
};

} // namespace bpftrace::ast
