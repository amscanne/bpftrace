#include <unordered_set>

#include "ast/ast.h"
#include "ast/passes/probe_expansion.h"
#include "ast/passes/recursion_check.h"
#include "ast/passes/resolve_imports.h"
#include "ast/visitor.h"
#include "providers/fentry.h"

namespace bpftrace::ast {

namespace {

const std::unordered_set<std::string> RECURSIVE_KERNEL_FUNCS = {
  "vmlinux:_raw_spin_lock",
  "vmlinux:_raw_spin_lock_irqsave",
  "vmlinux:_raw_spin_unlock_irqrestore",
  "vmlinux:queued_spin_lock_slowpath",
};

// Attaching to these kernel functions with fentry/fexit (kfunc/kretfunc)
// could lead to a recursive loop and kernel crash so we need additional
// generated BPF code to protect against this if one of these are being
// attached to.
bool is_recursive_func(const std::string &func_name)
{
  return RECURSIVE_KERNEL_FUNCS.contains(func_name);
}

class RecursionCheck : public Visitor<RecursionCheck> {
public:
  explicit RecursionCheck(ASTContext &ast, ExpandedAttachPoints &expanded)
      : ast_(ast), expanded_(expanded){};

  using Visitor<RecursionCheck>::visit;
  void visit(Probe &probe);
  void visit(Statement &stmt);

  void visit([[maybe_unused]] Subprog &subprog)
  {
    // Ignore potentially nested subprogs.
  }

  // Indicates whether the import is required.
  bool needs_import = false;

private:
  ASTContext &ast_;
  ExpandedAttachPoints &expanded_;
};

} // namespace

// This prevents an ABBA deadlock when attaching to spin lock internal
// functions e.g. "fentry:queued_spin_lock_slowpath".
//
// Specifically, if there are two hash maps (non percpu) being accessed by
// two different CPUs by two bpf progs then we can get in a situation where,
// because there are progs attached to spin lock internals, a lock is taken for
// one map while a different lock is trying to be acquired for the other map.
// This is specific to fentry/fexit (kfunc/kretfunc) as kprobes have kernel
// protections against this type of deadlock.
void RecursionCheck::visit(Probe &probe)
{
  auto &[provider, attach_point] = expanded_.attach_points[&probe];
  if ((provider->is<providers::FentryProvider>() ||
       provider->is<providers::FexitProvider>()) &&
      is_recursive_func(attach_point->name())) {
    probe.attach_points.front()->addWarning()
        << "Attaching to dangerous function: " << attach_point->name()
        << ". bpftrace has added mitigations to prevent a kernel "
           "deadlock but they may result in some lost events.";

    // Visit the main block to rewrite all returns to release
    // the recursive lock.
    visit(probe.block);

    // Rewrite the main block to execute the probe only if we
    // are we executing recursively.
    auto *ret = ast_.make_node<Jump>(JumpType::RETURN, Location(probe.loc));
    auto *none = ast_.make_node<None>(Location(probe.loc));
    auto *ret_block = ast_.make_node<BlockExpr>(StatementList({ ret }),
                                                none,
                                                Location(probe.loc));
    auto *probe_block = ast_.make_node<BlockExpr>(
        StatementList({}),
        ast_.make_node<IfExpr>(ast_.make_node<Call>("__try_set_recursion",
                                                    ExpressionList(),
                                                    Location(probe.loc)),
                               probe.block,
                               ret_block,
                               Location(probe.loc)),
        Location(probe.loc));
    probe.block = probe_block;
    needs_import = true;
    return;
  }
}

void RecursionCheck::visit(Statement &stmt)
{
  if (auto *jump = stmt.as<Jump>()) {
    if (jump->ident == JumpType::RETURN) {
      // Inject a call to the recursion check function.
      auto *none = ast_.make_node<None>(Location(jump->loc));
      auto *call = ast_.make_node<ExprStatement>(
          ast_.make_node<Call>("__unset_recursion",
                               ExpressionList(),
                               Location(jump->loc)),
          Location(jump->loc));
      auto *block = ast_.make_node<BlockExpr>(StatementList({ call, jump }),
                                              none,
                                              Location(jump->loc));
      stmt.value = ast_.make_node<ExprStatement>(block, Location(jump->loc));
    }
  }
}

Pass CreateRecursionCheckPass()
{
  return Pass::create("RecursionCheck",
                      [](ASTContext &ast,
                         ExpandedAttachPoints &expanded,
                         Imports &imports) -> Result<> {
                        auto recursion_check = RecursionCheck(ast, expanded);
                        recursion_check.visit(ast.root);
                        if (recursion_check.needs_import) {
                          return imports.import_any(*ast.root,
                                                    "stdlib/recursion_check");
                        }
                        return OK();
                      });
};

} // namespace bpftrace::ast
