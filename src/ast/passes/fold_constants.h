#pragma once

#include <iostream>
#include <string>
#include <unordered_set>

#include "ast/visitors.h"
#include "bpftrace.h"

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {
namespace ast {

// For now, this pass will simply fold all constant integer expressions and
// constant string expressions (concatenation) as well as the special case
// `str` with positional parameters. It is intended to remove this complexity
// elsewhere and from code generation, and is not necessarily intended to be a
// full constant folding pass that replaces the LLVM optimizations.
class FoldConstants : public Visitor {
public:
  explicit FoldConstants(Node *root, BPFtrace &bpftrace)
      : root_(root),
        bpftrace_(bpftrace),
  {
  }

  // The simplest way to write this pass given the current visitor plumbing is
  // to visit all types that may contain expressions, and manually call
  // `simplify` on each of those expressions. This will apply recursively, and
  // is done after the regular visit.
  void visit(Builtin &builtin) override;
  void visit(Call &call) override;
  void visit(Sizeof &szof) override;
  void visit(Offsetof &ofof) override;
  void visit(Map &map) override;
  void visit(Variable &var) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(Ternary &ternary) override;
  void visit(FieldAccess &acc) override;
  void visit(ArrayAccess &arr) override;
  void visit(Cast &cast) override;
  void visit(Tuple &tuple) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(AssignConfigVarStatement &assignment) override;
  void visit(VarDeclStatement &decl) override;
  void visit(If &if_node) override;
  void visit(Unroll &unroll) override;
  void visit(While &while_block) override;
  void visit(For &for_loop) override;
  void visit(Predicate &pred) override;

  void simplify(Expression **expr);
  void reduce(Expression *expr);

private:
  Node *root_;
  BPFtrace &bpftrace_;
  Expression *simplified_;
};

} // namespace ast
} // namespace bpftrace
