#include <bpf/bpf.h>
#include <cassert>

#include "arch/arch.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/probe_expansion.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "dwarf_parser.h"
#include "probe_matcher.h"
#include "util/strings.h"

namespace bpftrace::ast {

namespace {

class BuiltinChecker : public Visitor<BuiltinChecker> {
public:
  using Visitor<BuiltinChecker>::visit;
  void visit(Builtin &builtin);

  bool has_builtin_args = false;
  bool has_builtin_retval = false;
};

class FieldAnalyser : public Visitor<FieldAnalyser> {
public:
  explicit FieldAnalyser(BPFtrace &bpftrace, ExpansionResult &expansions)
      : bpftrace_(bpftrace), expansions_(expansions){};

  using Visitor<FieldAnalyser>::visit;
  void visit(Builtin &builtin);
  void visit(Identifier &identifier);
  void visit(Probe &probe);
  void visit(SizedType &type);

  BPFtrace &bpftrace_;
  ExpansionResult &expansions_;
};

} // namespace

void BuiltinChecker::visit(Builtin &builtin)
{
  if (builtin.ident == "args") {
    has_builtin_args = true;
  }
  if (builtin.ident == "__builtin_retval") {
    has_builtin_retval = true;
  }
}

void FieldAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "__builtin_curtask") {
    bpftrace_.btf_set_.insert("struct task_struct");
  }
}

void FieldAnalyser::visit(Identifier &identifier)
{
  bpftrace_.btf_set_.insert(identifier.ident);
}

void FieldAnalyser::visit(Probe &probe)
{
  BuiltinChecker checker;
  checker.visit(probe);

  for (auto *ap : probe.attach_points) {
    auto probe_type = probetype(ap->provider);
    auto prog_type = progtype(probe_type);
    auto attach_func = ap->func;

    switch (prog_type) {
      case BPF_PROG_TYPE_KPROBE:
        bpftrace_.btf_set_.insert("struct pt_regs");
        break;
      case BPF_PROG_TYPE_PERF_EVENT:
        bpftrace_.btf_set_.insert("struct bpf_perf_event_data");
        break;
      default:
        break;
    }

    // For each iterator probe, the context is pointing to specific struct,
    // make them resolved and available.
    if (probe_type == ProbeType::iter) {
      bpftrace_.btf_set_.insert("struct bpf_iter__" + attach_func);
    }

    // These are constructed elsehwere.
    if (probe_type != ProbeType::fentry && probe_type != ProbeType::fexit &&
        probe_type != ProbeType::rawtracepoint &&
        probe_type != ProbeType::uprobe) {
      continue;
    }

    // The rest is only if the arguments are BTF-based or uprobes.
    if (!checker.has_builtin_args && !checker.has_builtin_retval) {
      continue;
    }

    // load probe arguments into a special record type "struct
    // <probename>_args".
    std::shared_ptr<Struct> probe_args;
    if (expansions_.get_expansion(*ap) != ExpansionType::NONE) {
      std::set<std::string> matches;

      // Find all the matches for the wildcard..
      try {
        matches = bpftrace_.probe_matcher_->get_matches_for_ap(*ap);
      } catch (const WildcardException &e) {
        probe.addError() << e.what();
        return;
      }

      // ... and check if they share same arguments.
      std::shared_ptr<Struct> ap_args;
      for (const auto &match : matches) {
        // Both uprobes and fentry have a target (binary for uprobes, kernel
        // module for fentry).
        std::string func = match;
        std::string target = util::erase_prefix(func);
        std::string err;

        // Trying to attach to multiple fentry. If some of them fails on
        // argument resolution, do not fail hard, just print a warning and
        // continue with other functions.
        if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
          ap_args = bpftrace_.btf_->resolve_args(
              func, probe_type == ProbeType::fexit, true, false, err);

        } else if (probe_type == ProbeType::rawtracepoint) {
          ap_args = bpftrace_.btf_->resolve_raw_tracepoint_args(func, err);
        } else { // uprobe
          Dwarf *dwarf = bpftrace_.get_dwarf(target);
          if (dwarf)
            ap_args = dwarf->resolve_args(func);
          else
            ap->addWarning() << "No debuginfo found for " << target;
        }

        if (!ap_args) {
          ap->addWarning() << probetypeName(probe_type) << ap->func << ": "
                           << err;
          continue;
        }

        if (!probe_args)
          probe_args = ap_args;
        else if (*ap_args != *probe_args) {
          ap->addError() << "Probe has attach points with mixed arguments";
          break;
        }
      }
    } else {
      std::string err;
      // Resolving args for an explicit function failed, print an error and
      // fail.
      if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
        probe_args = bpftrace_.btf_->resolve_args(
            ap->func, probe_type == ProbeType::fexit, true, false, err);

      } else if (probe_type == ProbeType::rawtracepoint) {
        probe_args = bpftrace_.btf_->resolve_raw_tracepoint_args(ap->func, err);
      } else { // uprobe
        Dwarf *dwarf = bpftrace_.get_dwarf(ap->target);
        if (dwarf) {
          probe_args = dwarf->resolve_args(ap->func);
        } else {
          ap->addWarning() << "No debuginfo found for " << ap->target;
        }
        if (probe_args &&
            probe_args->fields.size() >= arch::Host::arguments().size()) {
          ap->addError() << "\'args\' builtin is not supported for "
                         << "probes with stack-passed arguments.";
        }
      }

      if (!probe_args) {
        ap->addError() << probetypeName(probe_type) << ap->func << ": " << err;
        return;
      }
    }

    // check if we already stored arguments for this probe.
    auto args = bpftrace_.structs.Lookup(probe.args_typename()).lock();
    if (args) {
      if (*args != *probe_args) {
        // we did, and it's different...trigger the error.
        ap->addError() << "Probe has attach points with mixed arguments";
      }
    } else {
      // store/save args for each ap for later processing.
      bpftrace_.structs.Add(probe.args_typename(), std::move(probe_args));
    }

    if (checker.has_builtin_retval) {
      // Load the retval for this probe. Note that this was *not* checked for
      // consistency at any point, so we preserve this behavior.
      const auto *retval = bpftrace_.structs.GetProbeArg(probe,
                                                         RETVAL_FIELD_NAME);
      if (!retval) {
        probe.addError() << "Probe uses return value, but not defined";
      }
    }
  }

  Visitor::visit(probe.block);
}

void FieldAnalyser::visit(SizedType &type)
{
  if (type.IsNoneTy()) {
    // Leave this as is, it will be resolved by the semantic analysis pass later
    // on, we only care about types that are half-resolved because they are used
    // in casts, etc. We don't have a type name or anything else relevant here.
  } else if (type.IsPtrTy()) {
    auto pointee = *type.GetPointeeTy();
    visit(pointee);
    if (!pointee.IsNoneTy()) {
      type = CreatePointer(pointee);
    }
  } else if (type.IsArrayTy()) {
    auto elem = *type.GetElementTy();
    visit(elem);
    if (!elem.IsNoneTy()) {
      type = CreateArray(type.GetNumElements(), elem);
    }
  } else if (type.IsRecordTy()) {
    if (bpftrace_.has_btf_data()) {
      auto ntype = bpftrace_.btf_->get_stype(type.GetName());
      if (!ntype.IsNoneTy() && ntype.IsRecordTy()) {
        bpftrace_.btf_->resolve_fields(ntype);
        // Load all elements recursively.
        for (auto &field : ntype.GetFields()) {
          visit(field.type);
        }
        type = ntype;
        return;
      }
    }
    bpftrace_.btf_set_.insert(type.GetName());
  }
}

Pass CreateFieldAnalyserPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b, ExpansionResult &expansions) {
    FieldAnalyser analyser(b, expansions);
    analyser.visit(ast.root);
  };

  return Pass::create("FieldAnalyser", fn);
};

} // namespace bpftrace::ast
