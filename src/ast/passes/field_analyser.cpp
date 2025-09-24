#include <bpf/bpf.h>
#include <cassert>
#include <map>

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

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 41482d6a (f)
class TypeResolver : public Visitor<TypeResolver> {
public:
  TypeResolver(BPFtrace &bpftrace, std::vector<Dwarf *> &&dwarves)
      : bpftrace_(bpftrace), dwarves_(std::move(dwarves)){};

  using Visitor<TypeResolver>::visit;
  void visit(Builtin &builtin);
  void visit(Identifier &identifier);
  void visit(SizedType &type);
  std::optional<SizedType> resolve_struct(const std::string &name);

private:
  BPFtrace &bpftrace_;
  std::vector<Dwarf *> dwarves_;
  std::map<std::string, std::shared_ptr<Struct>> resolved_;
};

<<<<<<< HEAD
=======
>>>>>>> e6c00df0 (field_analyser: simplify type resolution)
=======
>>>>>>> 41482d6a (f)
class FieldAnalyser : public Visitor<FieldAnalyser> {
public:
  explicit FieldAnalyser(BPFtrace &bpftrace, ExpansionResult &expansions)
      : bpftrace_(bpftrace), expansions_(expansions){};

  using Visitor<FieldAnalyser>::visit;
<<<<<<< HEAD
<<<<<<< HEAD
  void visit(Probe &probe);
=======
  void visit(Builtin &builtin);
  void visit(Identifier &identifier);
  void visit(Probe &probe);
  void visit(SizedType &type);
>>>>>>> e6c00df0 (field_analyser: simplify type resolution)
=======
  void visit(Probe &probe);
>>>>>>> 41482d6a (f)

  BPFtrace &bpftrace_;
  ExpansionResult &expansions_;
};

} // namespace

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 41482d6a (f)
auto *probe = get_probe(builtin, builtin.ident);
if (probe == nullptr)
  return;
for (auto *attach_point : probe->attach_points) {
  ProbeType type = probetype(attach_point->provider);

  if (type == ProbeType::tracepoint) {
    builtin_args_tracepoint(attach_point, builtin);
  }
}

ProbeType type = single_provider_type(probe);

if (type == ProbeType::invalid) {
  builtin.addError()
      << "The args builtin can only be used within the context of a single "
         "probe type, e.g. \"probe1 {args}\" is valid while "
         "\"probe1,probe2 {args}\" is not.";
} else if (type == ProbeType::fentry || type == ProbeType::fexit ||
           type == ProbeType::uprobe || type == ProbeType::rawtracepoint) {
  for (auto *attach_point : probe->attach_points) {
    if (attach_point->target == "bpf") {
      builtin.addError() << "The args builtin cannot be used for "
                            "'fentry/fexit:bpf' probes";
      return;
    }
  }
  auto type_name = probe->args_typename();
  builtin.builtin_type = CreateRecord(type_name,
                                      bpftrace_.structs.Lookup(type_name));
  if (builtin.builtin_type.GetFieldCount() == 0)
    builtin.addError() << "Cannot read function parameters";

  builtin.builtin_type.MarkCtxAccess();
  builtin.builtin_type.is_funcarg = true;
  builtin.builtin_type.SetAS(type == ProbeType::uprobe ? AddrSpace::user
                                                       : AddrSpace::kernel);
  // We'll build uprobe args struct on stack
  if (type == ProbeType::uprobe)
    builtin.builtin_type.is_internal = true;
} else if (type != ProbeType::tracepoint) // no special action for
                                          // tracepoint
<<<<<<< HEAD
=======
=======
{
  builtin.addError() << "The args builtin can only be used with "
                        "tracepoint/fentry/uprobe probes ("
                     << type << " used here)";
}

>>>>>>> 41482d6a (f)
void BuiltinChecker::visit(Builtin &builtin)
{
  if (builtin.ident == "args") {
    has_builtin_args = true;
  }
  if (builtin.ident == "__builtin_retval") {
    has_builtin_retval = true;
  }
}

void TypeResolver::visit(Builtin &builtin)
{
  std::string tracepoint_struct = TracepointFormatParser::get_struct_name(
      *attach_point);
  structs[tracepoint_struct] =
      bpftrace_.structs.Lookup(tracepoint_struct).lock();
}

if (type == ProbeType::kretprobe || type == ProbeType::uretprobe) {
  builtin.builtin_type = CreateUInt64();
} else if (type == ProbeType::fentry || type == ProbeType::fexit) {
  const auto *arg = bpftrace_.structs.GetProbeArg(*probe, RETVAL_FIELD_NAME);
  if (arg) {
    builtin.builtin_type = arg->type;
  } else
    builtin.addError() << "Can't find a field " << RETVAL_FIELD_NAME;
} else {
  builtin.addError()
      << "The retval builtin can only be used with 'kretprobe' and "
      << "'uretprobe' and 'fentry' probes"
      << (type == ProbeType::tracepoint ? " (try to use args.ret instead)"
                                        : "");
}
// For kretprobe, fentry, fexit -> AddrSpace::kernel
// For uretprobe -> AddrSpace::user
builtin.builtin_type.SetAS(find_addrspace(type));

std::string tracepoint_struct = TracepointFormatParser::get_struct_name(
    *attach_point);
builtin.builtin_type = CreateRecord(tracepoint_struct,
                                    bpftrace_.structs.Lookup(
                                        tracepoint_struct));
builtin.builtin_type.SetAS(attach_point->target == "syscalls"
                               ? AddrSpace::user
                               : AddrSpace::kernel);
builtin.builtin_type.MarkCtxAccess();
builtin.builtin_type.is_tparg = true;

std::optional<SizedType> TypeResolver::resolve_struct(const std::string &name)
{
  // Check if this has already been resolved.
  auto it = resolved_.find(name);
  if (it != resolved_.end()) {
    return CreateRecord(name, it->second);
  }

  // It may have been resolved transitively.
  auto existing = bpftrace_.structs.Lookup(name).lock();
  if (existing && !existing->fields.empty()) {
    resolved_.emplace(name, existing);
    return CreateRecord(name, existing);
  }

  // Does it need BTF?
  if (bpftrace_.has_btf_data()) {
    auto type = bpftrace_.btf_->get_stype(name);
    if (!type.IsNoneTy()) {
      resolved_.emplace(name, type.GetStruct());
      // Recursively resolve all fields.
      for (const auto &field : type.GetFields()) {
        if (field.type.IsRecordTy()) {
          resolve_struct(field.type.GetName());
        }
      }
      return type;
    }
  }

  // This might be a dwarf type? See if there any matching providers
  // and then attempt to resolve the type.
  auto new_struct = bpftrace_.structs.LookupOrAdd(name, 0, false);
  auto type = CreateRecord(name, new_struct);
  for (auto *dwarf : dwarves_) {
    try {
      dwarf->resolve_fields(type);
    } catch (const std::exception &e) {
      continue;
    }
    if (type.GetFieldCount() > 0) {
      for (const auto &field : type.GetFields()) {
        if (field.type.IsRecordTy()) {
          resolve_struct(field.type.GetName());
        }
      }
      resolved_.emplace(name, new_struct.lock());
      return type;
    }
  }

  return std::nullopt;
}

void TypeResolver::visit(Builtin &builtin)
{
  // This will be resolved by the semantic analyser.
  if (builtin.ident == "__builtin_curtask") {
    bpftrace_.btf_set_.insert("struct task_struct");
  }
}

<<<<<<< HEAD
void FieldAnalyser::visit(Identifier &identifier)
>>>>>>> e6c00df0 (field_analyser: simplify type resolution)
{
  builtin.addError() << "The args builtin can only be used with "
                        "tracepoint/fentry/uprobe probes ("
                     << type << " used here)";
}

void BuiltinChecker::visit(Builtin &builtin)
{
  if (builtin.ident == "args") {
    has_builtin_args = true;
  }
  if (builtin.ident == "__builtin_retval") {
    has_builtin_retval = true;
  }
}

void TypeResolver::visit(Builtin &builtin)
{
  std::string tracepoint_struct = TracepointFormatParser::get_struct_name(
      *attach_point);
  structs[tracepoint_struct] =
      bpftrace_.structs.Lookup(tracepoint_struct).lock();
}

if (type == ProbeType::kretprobe || type == ProbeType::uretprobe) {
  builtin.builtin_type = CreateUInt64();
} else if (type == ProbeType::fentry || type == ProbeType::fexit) {
  const auto *arg = bpftrace_.structs.GetProbeArg(*probe, RETVAL_FIELD_NAME);
  if (arg) {
    builtin.builtin_type = arg->type;
  } else
    builtin.addError() << "Can't find a field " << RETVAL_FIELD_NAME;
} else {
  builtin.addError()
      << "The retval builtin can only be used with 'kretprobe' and "
      << "'uretprobe' and 'fentry' probes"
      << (type == ProbeType::tracepoint ? " (try to use args.ret instead)"
                                        : "");
}
// For kretprobe, fentry, fexit -> AddrSpace::kernel
// For uretprobe -> AddrSpace::user
builtin.builtin_type.SetAS(find_addrspace(type));

std::string tracepoint_struct = TracepointFormatParser::get_struct_name(
    *attach_point);
builtin.builtin_type = CreateRecord(tracepoint_struct,
                                    bpftrace_.structs.Lookup(
                                        tracepoint_struct));
builtin.builtin_type.SetAS(attach_point->target == "syscalls"
                               ? AddrSpace::user
                               : AddrSpace::kernel);
builtin.builtin_type.MarkCtxAccess();
builtin.builtin_type.is_tparg = true;

std::optional<SizedType> TypeResolver::resolve_struct(const std::string &name)
{
  // Check if this has already been resolved.
  auto it = resolved_.find(name);
  if (it != resolved_.end()) {
    return CreateRecord(name, it->second);
  }

  // It may have been resolved transitively.
  auto existing = bpftrace_.structs.Lookup(name).lock();
  if (existing && !existing->fields.empty()) {
    resolved_.emplace(name, existing);
    return CreateRecord(name, existing);
  }

  // Does it need BTF?
  if (bpftrace_.has_btf_data()) {
    auto type = bpftrace_.btf_->get_stype(name);
    if (!type.IsNoneTy()) {
      resolved_.emplace(name, type.GetStruct());
      // Recursively resolve all fields.
      for (const auto &field : type.GetFields()) {
        if (field.type.IsRecordTy()) {
          resolve_struct(field.type.GetName());
        }
      }
      return type;
    }
  }

  // This might be a dwarf type? See if there any matching providers
  // and then attempt to resolve the type.
  auto new_struct = bpftrace_.structs.LookupOrAdd(name, 0, false);
  auto type = CreateRecord(name, new_struct);
  for (auto *dwarf : dwarves_) {
    try {
      dwarf->resolve_fields(type);
    } catch (const std::exception &e) {
      continue;
    }
    if (type.GetFieldCount() > 0) {
      for (const auto &field : type.GetFields()) {
        if (field.type.IsRecordTy()) {
          resolve_struct(field.type.GetName());
        }
      }
      resolved_.emplace(name, new_struct.lock());
      return type;
    }
  }

  return std::nullopt;
}

void TypeResolver::visit(Builtin &builtin)
{
  // This will be resolved by the semantic analyser.
  if (builtin.ident == "__builtin_curtask") {
    bpftrace_.btf_set_.insert("struct task_struct");
  }
}

void TypeResolver::visit(Identifier &identifier)
{
=======
void TypeResolver::visit(Identifier &identifier)
{
>>>>>>> 41482d6a (f)
  // See above; this is resolved by the semantic analyser.
  bpftrace_.btf_set_.insert(identifier.ident);
}

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 41482d6a (f)
void TypeResolver::visit(SizedType &type)
{
  if (type.IsNoneTy()) {
    // Leave this as is, it will be resolved by the semantic analysis pass later
    // on, we only care about types that are half-resolved because they are used
    // in casts, etc. We don't have a type name or anything else relevant here.
  } else if (type.IsPtrTy()) {
    auto pointee = *type.GetPointeeTy();
    visit(pointee);
    type = CreatePointer(pointee, type.GetAS());
  } else if (type.IsArrayTy()) {
    auto elem = *type.GetElementTy();
    visit(elem);
    type = CreateArray(type.GetNumElements(), elem);
  } else if (type.IsRecordTy()) {
    auto ntype = resolve_struct(type.GetName());
    if (ntype) {
      type = *ntype;
    } else {
      bpftrace_.btf_set_.insert(type.GetName());
    }
  }
}

static std::shared_ptr<const Struct> get_args(const AttachPoint &ap)
{
  auto probe_type = probetype(ap.provider);
  auto prog_type = progtype(probe_type);
  auto attach_func = ap.func;

  std::string cast_type = is_tparg ? TracepointFormatParser::get_struct_name(
                                         *current_attach_point_)
                                   : type.GetName();

  // This overwrites the stored type!
  type = CreateRecord(cast_type, bpftrace_.structs.Lookup(cast_type));
  if (is_ctx)
    type.MarkCtxAccess();
  type.is_tparg = is_tparg;
  type.is_internal = is_internal;
  type.is_funcarg = is_funcarg;
  // Restore the addrspace info
  // struct MyStruct { const int* a; };  $s = (struct MyStruct *)arg0;  $s->a
  type.SetAS(addrspace);

  switch (prog_type) {
    case BPF_PROG_TYPE_KPROBE:
      return ident_to_record() return bpftrace_.btf_set_.insert(
          "struct pt_regs");
      break;
    case BPF_PROG_TYPE_PERF_EVENT:
      bpftrace_.btf_set_.insert("struct bpf_perf_event_data");
      break;
    default:
      break;
  }
}

void FieldAnalyser::visit(Probe &probe)
{
  BuiltinChecker checker;
  checker.visit(probe);

  bool has_typed_attachpoint = false;
  bool needs_strict_equality = checker.has_builtin_args ||
                               checker.has_builtin_retval;

  std::vector<Dwarf *> dwarves;
<<<<<<< HEAD
=======
void FieldAnalyser::visit(Probe &probe)
{
  BuiltinChecker checker;
  checker.visit(probe);

>>>>>>> e6c00df0 (field_analyser: simplify type resolution)
=======
>>>>>>> 41482d6a (f)
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

<<<<<<< HEAD
<<<<<<< HEAD
    // These are constructed elsewhere.
=======
    // These are constructed elsehwere.
>>>>>>> e6c00df0 (field_analyser: simplify type resolution)
=======
    // These are constructed elsewhere.
>>>>>>> 41482d6a (f)
    if (probe_type != ProbeType::fentry && probe_type != ProbeType::fexit &&
        probe_type != ProbeType::rawtracepoint &&
        probe_type != ProbeType::uprobe) {
      continue;
    }
<<<<<<< HEAD
<<<<<<< HEAD
    has_typed_attachpoint = true;

=======

    // The rest is only if the arguments are BTF-based or uprobes.
    if (!checker.has_builtin_args && !checker.has_builtin_retval) {
      continue;
    }
=======
    has_typed_attachpoint = true;
>>>>>>> 41482d6a (f)

>>>>>>> e6c00df0 (field_analyser: simplify type resolution)
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
          if (dwarf) {
            ap_args = dwarf->resolve_args(func);
            dwarves.push_back(dwarf);
          } else {
            ap->addWarning() << "No debuginfo found for " << target;
          }
        }

        if (!probe_args) {
          probe_args = ap_args;
        } else if (probe_args && ap_args && needs_strict_equality &&
                   *ap_args != *probe_args) {
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
          dwarves.push_back(dwarf);
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
        ap->addError() << "Failed to resolve arguments for " << ap->func << ": "
                       << err;
      }
    }

    // check if we already stored arguments for this probe.
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 41482d6a (f)
    if (probe_args) {
      auto args = bpftrace_.structs.Lookup(probe.args_typename()).lock();
      if (args) {
        if (needs_strict_equality && *args != *probe_args) {
          // we did, and it's different...trigger the error.
          ap->addError() << "Probe has attach points with mixed arguments";
<<<<<<< HEAD
        }
      } else {
        // store/save args for each ap for later processing.
        bpftrace_.structs.Add(probe.args_typename(), std::move(probe_args));
      }
    }
  }

  // Resolve all the types found in other type expressions.
  TypeResolver resolver(bpftrace_, std::move(dwarves));
  if (has_typed_attachpoint && checker.has_builtin_args) {
    auto args = bpftrace_.structs.Lookup(probe.args_typename()).lock();
    if (!args) {
      probe.addError() << "Probe uses args, but not defined";
    } else {
      for (const auto &field : args->fields) {
        resolver.visit(field.type);
      }
    }
  }
  if (has_typed_attachpoint && checker.has_builtin_retval) {
    // Load the retval for this probe. Note that this was *not* checked for
    // consistency at any point, so we preserve this behavior.
    const auto *retval = bpftrace_.structs.GetProbeArg(probe,
                                                       RETVAL_FIELD_NAME);
    if (!retval) {
      probe.addError() << "Probe uses return value, but not defined";
    } else {
      resolver.visit(retval->type);
    }
  }
  // Catch all other explicit types.
  resolver.visit(probe.block);
=======
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
=======
>>>>>>> 41482d6a (f)
        }
      } else {
        // store/save args for each ap for later processing.
        bpftrace_.structs.Add(probe.args_typename(), std::move(probe_args));
      }
    }
  }
<<<<<<< HEAD
>>>>>>> e6c00df0 (field_analyser: simplify type resolution)
=======

  // Resolve all the types found in other type expressions.
  TypeResolver resolver(bpftrace_, std::move(dwarves));
  if (has_typed_attachpoint && checker.has_builtin_args) {
    auto args = bpftrace_.structs.Lookup(probe.args_typename()).lock();
    if (!args) {
      probe.addError() << "Probe uses args, but not defined";
    } else {
      for (const auto &field : args->fields) {
        resolver.visit(field.type);
      }
    }
  }
  if (has_typed_attachpoint && checker.has_builtin_retval) {
    // Load the retval for this probe. Note that this was *not* checked for
    // consistency at any point, so we preserve this behavior.
    const auto *retval = bpftrace_.structs.GetProbeArg(probe,
                                                       RETVAL_FIELD_NAME);
    if (!retval) {
      probe.addError() << "Probe uses return value, but not defined";
    } else {
      resolver.visit(retval->type);
    }
  }
  // Catch all other explicit types.
  resolver.visit(probe.block);
>>>>>>> 41482d6a (f)
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
