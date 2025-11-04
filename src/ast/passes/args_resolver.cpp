#include <bpf/bpf.h>
#include <cassert>

#include "ast/passes/args_resolver.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "dwarf_parser.h"
#include "probe_matcher.h"
#include "probe_types.h"
#include "util/result.h"

namespace bpftrace::ast {

char ArgParseError::ID;

void ArgParseError::log(llvm::raw_ostream &OS) const
{
  OS << "Could not parse arguments of \"" << probe_name_ << "\": " << detail_;
}

namespace {

class ArgsResolver : public Visitor<ArgsResolver> {
public:
  explicit ArgsResolver(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<ArgsResolver>::visit;
  void visit(Expression &expr);
  void visit(Builtin &builtin);
  void visit(Probe &probe);

private:
  void resolve_args(Probe &probe);
  Result<> resolve_args(const AttachPoint &ap);
  Expression generate(const SizedType &type, size_t index);
  Expression generate(const SizedType &type, const std::string &name);

  ASTContext &ast_;
  BPFtrace &bpftrace_;

  std::vector<std::pair<std::string, SizedType>> register_args_;
  std::optional<SizedType> btf_args_;
};

} // namespace

void ArgsResolver::visit(Expression &expr)
{
  Visitor::visit(expr);

  // Resolve `__builtin_retval` suitably.
  if (auto *builtin = expr.as<Builtin>()) {
    if (builtin->ident == "__builtin_retval") {
    }
  }

  // Resolve `args` directly, if suitable.
  if (auto *args = expr.as<Builtin>()) {
    if (args->ident == "args" && btf_args_) {
      auto *ctx = ast_.make_node<Builtin>(expr.node().loc, "ctx");
      auto *cast = ast_.make_node<Cast>(expr.node().loc, *btf_args_, ctx);
      expr.value = cast;
      return;
    }
  }

  if (auto *acc = expr.as<FieldAccess>()) {
    if (auto *args = acc->expr.as<Builtin>()) {
      if (args->ident == "args") {
      }
    }
  }
}

Result<> ArgsResolver::resolve_args(const AttachPoint &ap)
{
  auto probe_type = probetype(ap.provider);
  switch (probe_type) {
    case ProbeType::fentry:
    case ProbeType::fexit: {
      auto args = bpftrace_.btf_->resolve_args(
          ap.func, probe_type == ProbeType::fexit, true, false);
      if (!args) {
        return args.takeError();
      }
      btf_args_.emplace(CreateRecord(std::move(*args)));
      break;
    }
    case ProbeType::tracepoint: {
      auto args = bpftrace_.btf_->resolve_tracepoint_args(ap.func);
    }
    case ProbeType::rawtracepoint: {
      auto args = bpftrace_.btf_->resolve_raw_tracepoint_args(ap.func);
      if (!args) {
        return args.takeError();
      }
      btf_args_.emplace(CreateRecord(std::move(*args)));
      break;
    }
    case ProbeType::uprobe: {
      Dwarf *dwarf = bpftrace_.get_dwarf(ap.target);
      if (dwarf) {
        register_args_ = dwarf->resolve_args(ap.func);
      }
      break;
    }
    default:
      break;
  }
  return OK();
}

void ArgsResolver::resolve_args(Probe &probe)
{
  if (probe.attach_points.empty())
    return; // No args available.

  // Everything should be expanded by now.
  assert(probe.attach_points.size() == 1);
  auto *ap = probe.attach_points.at(0);

  auto probe_args = resolve_args(*ap);
  if (!probe_args) {
    ap->addError() << probe_args.takeError();
    return;
  }
}

void ArgsResolver::visit(Probe &probe)
{
  register_args_.clear();
  btf_args_.reset();
  resolve_args(probe);
  Visitor::visit(probe);
}

class ArgsVerifier : public Visitor<ArgsVerifier> {
public:
  using Visitor<ArgsVerifier>::visit;
  void visit(Builtin &builtin);
};

void ArgsResolver::visit(Builtin &builtin)
{
  if (builtin.ident == "args" || builtin.ident == "__builtin_retval") {
    builtin.addError() << "Unable to resolve arguments.";
  }
}

Pass CreateArgsResolverPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    ArgsResolver resolver(ast, b);
    resolver.visit(ast.root);
    ArgsVerifier verifier;
    verifier.visit(ast.root);
  };

  return Pass::create("ArgsResolver", fn);
};

} // namespace bpftrace::ast
