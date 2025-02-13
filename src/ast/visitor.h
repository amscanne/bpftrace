#pragma once

#include <string>

#include "ast/ast.h"
#include "ast/error.h"

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
  // R_int is used internally to wrap visitAndReplace and visitImpl, so that
  // these are not mistaken used by external APIs. These need to be unwrapped
  // by `merge` before they can be returned.
  using R_int = std::conditional<std::is_void_v<R>, std::monostate, R>::type;

  // See above; specific replace methods may be defined.
  template <typename T>
  T *replace(T *node, [[maybe_unused]] R *result)
  {
    return node;
  }

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
    return merge(visitImpl(call.vargs));
  }
  R visit(Sizeof &szof)
  {
    return merge(visitAndReplace(&szof.expr));
  }
  R visit(Offsetof &ofof)
  {
    return merge(visitAndReplace(&ofof.expr));
  }
  R visit(Map &map)
  {
    return merge(visitAndReplace(&map.key_expr));
  }
  R visit(Binop &binop)
  {
    return merge(visitAndReplace(&binop.left), visitAndReplace(&binop.right));
  }
  R visit(Unop &unop)
  {
    return merge(visitAndReplace(&unop.expr));
  }
  R visit(Ternary &ternary)
  {
    return merge(visitAndReplace(&ternary.cond),
                 visitAndReplace(&ternary.left),
                 visitAndReplace(&ternary.right));
  }
  R visit(FieldAccess &acc)
  {
    return merge(visitAndReplace(&acc.expr));
  }
  R visit(ArrayAccess &arr)
  {
    return merge(visitAndReplace(&arr.expr), visitAndReplace(&arr.indexpr));
  }
  R visit(Cast &cast)
  {
    return merge(visitAndReplace(&cast.expr));
  }
  R visit(Tuple &tuple)
  {
    return merge(visitImpl(tuple.elems));
  }
  R visit(ExprStatement &expr)
  {
    return merge(visitAndReplace(&expr.expr));
  }
  R visit(AssignMapStatement &assignment)
  {
    return merge(visitAndReplace(&assignment.map),
                 visitAndReplace(&assignment.expr));
  }
  R visit(AssignVarStatement &assignment)
  {
    return merge(visitAndReplace(&assignment.var),
                 visitAndReplace(&assignment.expr));
  }
  R visit(AssignConfigVarStatement &assignment)
  {
    return merge(visitAndReplace(&assignment.expr));
  }
  R visit(VarDeclStatement &decl)
  {
    return merge(visitAndReplace(&decl.var));
  }
  R visit(If &if_node)
  {
    return merge(visitAndReplace(&if_node.cond),
                 visitAndReplace(&if_node.if_block),
                 visitAndReplace(&if_node.else_block));
  }
  R visit(Jump &jump)
  {
    return merge(visitAndReplace(&jump.return_value));
  }
  R visit(Unroll &unroll)
  {
    return merge(visitAndReplace(&unroll.expr), visitAndReplace(&unroll.block));
  }
  R visit(While &while_block)
  {
    return merge(visitAndReplace(&while_block.cond),
                 visitAndReplace(&while_block.block));
  }
  R visit(For &for_loop)
  {
    return merge(visitAndReplace(&for_loop.decl),
                 visitAndReplace(&for_loop.expr));
  }
  R visit(Predicate &pred)
  {
    return merge(visitAndReplace(&pred.expr));
  }
  R visit(Probe &probe)
  {
    return merge(visitImpl(probe.attach_points),
                 visitAndReplace(&probe.pred),
                 visitAndReplace(&probe.block));
  }
  R visit(Config &config)
  {
    return merge(visitImpl(config.stmts));
  }
  R visit(Block &block)
  {
    return merge(visitImpl(block.stmts));
  }
  R visit(Subprog &subprog)
  {
    return merge(visitImpl(subprog.args), visitImpl(subprog.stmts));
  }
  R visit(Program &program)
  {
    return merge(visitImpl(program.functions),
                 visitImpl(program.probes),
                 visitAndReplace(&program.config));
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
      auto rval = visitAndReplace(&ptr);
      assert(ptr == &t); // Should not be modified.
      return rval;
    } else {
      visitAndReplace(&ptr);
      assert(ptr == &t); // See above.
    }
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
  R visit(std::variant<Ts *...> var)
  {
    return std::visit(
        [this](auto &value) -> R { return visitAndReplace(&value); }, var);
  }
  template <typename T>
  R visit(std::vector<T *> &var)
  {
    for (auto &value : var) {
      visitAndReplace(&value);
    }
    return default_value();
  }
  template <typename T>
  R visit(std::optional<T *> &var)
  {
    if (var) {
      return visitAndReplace(&(*var));
    }
    return default_value();
  }

  // This is a convenience for dispatching directly from a pointer type, it
  // does not allow for replacement of this specific instance.
  template <typename T>
  R visit(T *ptr)
  {
    if (ptr)
      return merge(visitImpl(*ptr));
    return default_value();
  }

  template <typename T>
  R_int visitAndReplace(T **t)
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
      return R_int();
    }
  }

  // These are the runtime-type adaptors that are currently required for
  // Expression and Statement, but can be removed by encoding this type
  // information into the AST directly.
  template <typename Orig, typename T, typename... Ts>
  R_int tryVisitAndReplace(Orig **node)
  {
    if (auto *t = dynamic_cast<T>(*node)) {
      auto rval = visitAndReplace(&t);
      *node = static_cast<Orig *>(t); // Copy the modification.
      return rval;
    } else if constexpr (sizeof...(Ts) != 0) {
      return tryVisitAndReplace<Orig, Ts...>(node);
    }
    return R_int();
  }
  R_int visitAndReplace(Expression **expr)
  {
    return tryVisitAndReplace<Expression,
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
  R_int visitAndReplace(Statement **stmt)
  {
    return tryVisitAndReplace<Statement,
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

private:
  template <typename T>
  R_int visitImpl(T &t)
  {
    Impl *impl = static_cast<Impl *>(this);
    if constexpr (std::is_void_v<R>) {
      impl->visit(t);
      return R_int();
    } else {
      return impl->visit(t);
    }
  }
  R default_value()
  {
    if constexpr (!std::is_void_v<R>) {
      return R();
    }
  }
  template <typename T, typename... Args>
  R merge(T &&first, [[maybe_unused]] Args &&...args)
  {
    if constexpr (!std::is_void_v<R>) {
      return std::move(first);
    }
  }
  template <typename T, typename... Args>
  R merge(ErrorOr<T> &&first, ErrorOr<T> &&second, Args &&...args)
  {
    if constexpr (sizeof...(Args) == 0) {
      return R(std::move(first), std::move(second));
    } else {
      // Recursively merge the remaining elements, which will essentially
      // aggregate all generated errors and warnings.
      return merge(merge(std::move(first), std::move(second)),
                   std::move(args)...);
    }
  }
};

} // namespace bpftrace::ast
