#include "ast/passes/pid_filter_pass.h"
#include "ast/ast.h"
#include "ast/context.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

namespace {

class PidFilterPass : public Visitor<PidFilterPass> {
public:
  explicit PidFilterPass(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace)
  {
  }

  using Visitor<PidFilterPass>::visit;
  void visit(Probe &probe);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
};

} // namespace

// If the probe can't filter by pid when attaching
// then we inject custom AST to filter by pid.
// Note: this doesn't work for AOT as the code has already
// been generated
static bool probe_needs_pid_filter(AttachPoint &ap)
{
  ProbeType type = probetype(ap.provider);

  switch (type) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
    case ProbeType::rawtracepoint:
      return true;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
    case ProbeType::invalid:
    case ProbeType::iter:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::software:
    case ProbeType::hardware:
    // We don't filter by pid for BEGIN/END probes
    case ProbeType::special:
      return false;
  }

  return false;
}

static Statement create_pid_filter(ASTContext &ast,
                                   int pid,
                                   const Location &loc)
{
  std::vector<Statement> stmts(
      { Statement(ast.make_node<Jump>(JumpType::RETURN, Location(loc))) });
  Expression cond(ast.make_node<Binop>(
      Expression(ast.make_node<Builtin>("pid", Location(loc))),
      Operator::NE,
      Expression(ast.make_node<Integer>(pid, Location(loc))),
      Location(loc)));
  Statement filter(ast.make_node<If>(
      cond,
      ast.make_node<Block>(std::move(stmts), Location(loc)),
      ast.make_node<Block>(std::vector<Statement>(), Location(loc)),
      Location(loc)));
  return filter;
}

void PidFilterPass::visit(Probe &probe)
{
  const auto pid = bpftrace_.pid();
  if (!pid.has_value() || probe.block.stmts.empty()) {
    return;
  }

  for (AttachPoint &ap : probe.attach_points) {
    if (probe_needs_pid_filter(ap)) {
      probe.block.stmts.insert(probe.block.stmts.begin(),
                               create_pid_filter(ast_, *pid, probe.loc));
      return;
    }
  }
}

Pass CreatePidFilterPass()
{
  return Pass::create("PidFilter", [](ASTContext &ast, BPFtrace &b) {
    auto pid_filter = PidFilterPass(ast, b);
    pid_filter.visit(ast.root);
  });
};

} // namespace bpftrace::ast
