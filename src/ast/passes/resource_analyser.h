#pragma once

#include <iostream>
#include <optional>
#include <sstream>
#include <stddef.h>
#include <string>

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "ast/visitors.h"
#include "required_resources.h"

namespace bpftrace {
namespace ast {

// Resource analysis pass on AST
//
// This pass collects information on what runtime resources a script needs.
// For example, how many maps to create, what sizes the keys and values are,
// all the async printf argument types, etc.
//
// TODO(danobi): Note that while complete resource collection in this pass is
// the goal, there are still places where the goal is not yet realized. For
// example the helper error metadata is still being collected during codegen.
class ResourceAnalyser : public Visitor {
public:
  ResourceAnalyser(ASTContext &ctx,
                   BPFtrace &bpftrace,
                   std::ostream &out = std::cerr);

  std::optional<RequiredResources> analyse();

private:
  void visit(Probe &probe) override;
  void visit(Subprog &subprog) override;
  void visit(Builtin &map) override;
  void visit(Call &call) override;
  void visit(Map &map) override;
  void visit(Tuple &tuple) override;
  void visit(For &f) override;
  void visit(Ternary &ternary) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(VarDeclStatement &decl) override;

  // Determines whether the given function uses userspace symbol resolution.
  // This is used later for loading the symbol table into memory.
  bool uses_usym_table(const std::string &fun);

  bool exceeds_stack_limit(size_t size);

  void maybe_allocate_map_key_buffer(const Map &map);

  void update_map_info(Map &map);
  void update_variable_info(Variable &var);

  RequiredResources resources_;
  BPFtrace &bpftrace_;
  std::ostream &out_;
  std::ostringstream err_;
  // Current probe we're analysing
  Probe *probe_;

  int next_map_id_ = 0;
};

Pass CreateResourcePass();

} // namespace ast
} // namespace bpftrace
