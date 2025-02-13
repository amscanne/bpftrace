#include "portability_analyser.h"

#include <cstdlib>

#include "log.h"
#include "types.h"

namespace bpftrace::ast {

void PortabilityAnalyser::visit(PositionalParameter &param)
{
  // Positional params are only known at runtime. Currently, codegen directly
  // embeds positional params into the bytecode but that does not work for AOT.
  //
  // In theory we could allow positional params for AOT and just embed the
  // values into the bytecode but there's really no point to that as:
  //
  //   * that would mislead the user into thinking there's positional param
  //   support
  //   * the user can just hard code the values into their script
  LOG(ERROR, param.loc, err_)
      << "AOT does not yet support positional parameters";
}

void PortabilityAnalyser::visit(Builtin &builtin)
{
  // `struct task_struct` is unstable across kernel versions and configurations.
  // This makes it inherently unportable. We must block it until we support
  // field access relocations.
  if (builtin.ident == "curtask") {
    LOG(ERROR, builtin.loc, err_)
        << "AOT does not yet support accessing `curtask`";
  }
}

void PortabilityAnalyser::visit(Call &call)
{
  for (Expression *expr : call.vargs)
    visit(*expr);

  // kaddr() and uaddr() both resolve symbols -> address during codegen and
  // embeds the values into the bytecode. For AOT to support kaddr()/uaddr(),
  // the addresses must be resolved at runtime and fixed up during load time.
  //
  // cgroupid can vary across systems just like how a process does not
  // necessarily share the same PID across multiple systems. cgroupid() is also
  // resolved during codegen and the value embedded into the bytecode.  For AOT
  // to support cgroupid(), the cgroupid must be resolved at runtime and fixed
  // up during load time.
  if (call.func == "kaddr" || call.func == "uaddr" || call.func == "cgroupid") {
    LOG(ERROR, call.loc, err_)
        << "AOT does not yet support " << call.func << "()";
  }
}

void PortabilityAnalyser::visit(Cast &cast)
{
  visit(*cast.expr);

  // The goal here is to block arbitrary field accesses but still allow `args`
  // access. `args` for tracepoint is fairly stable and should be considered
  // portable. `args` for k[ret]funcs are type checked by the kernel and may
  // also be considered stable. For AOT to fully support field accesses, we
  // need to relocate field access at runtime.
  LOG(ERROR, cast.loc, err_) << "AOT does not yet support struct casts";
}

void PortabilityAnalyser::visit(AttachPoint &ap)
{
  auto type = probetype(ap.provider);

  // USDT probes require analyzing a USDT enabled binary for precise offsets
  // and argument information. This analyzing is currently done during codegen
  // and offsets and type information is embedded into the bytecode. For AOT
  // support, this analyzing must be done during runtime and fixed up during
  // load time.
  if (type == ProbeType::usdt) {
    LOG(ERROR, ap.loc, err_) << "AOT does not yet support USDT probes";
  }
  // While userspace watchpoint probes are technically portable from codegen
  // point of view, they require a PID or path via cmdline to resolve address.
  // watchpoint probes are also API-unstable and need a further change
  // (see https://github.com/bpftrace/bpftrace/issues/1683).
  //
  // So disable for now and re-evalulate at another point.
  else if (type == ProbeType::watchpoint ||
           type == ProbeType::asyncwatchpoint) {
    LOG(ERROR, ap.loc, err_) << "AOT does not yet support watchpoint probes";
  }
}

Pass CreatePortabilityPass(std::ostream &out)
{
  return Pass::create("PortabilityAnalyser", [&out](ASTContext &ast) {
    PortabilityAnalyser analyser;
    analyser.visit(ast.root);

    std::string err = analyser.error();
    if (!err.empty()) {
      // Used by runtime test framework to know when to skip an AOT test.
      if (std::getenv("__BPFTRACE_NOTIFY_AOT_PORTABILITY_DISABLED"))
        std::cout << "__BPFTRACE_NOTIFY_AOT_PORTABILITY_DISABLED" << std::endl;
      out << err;
      return Failure(std::move(err));
    }

    return Success();
  });
}

} // namespace bpftrace::ast
