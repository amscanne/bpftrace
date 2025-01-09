#include "field_analyser.h"

#include <cassert>
#include <iostream>

#include "arch/arch.h"
#include "dwarf_parser.h"
#include "log.h"
#include "probe_matcher.h"

namespace bpftrace::ast {

void FieldAnalyser::visit(PointerTypeSpec &ty)
{
  Visit(*ty.elem);
  ty.type = CreatePointer(ty.elem->type);
}

void FieldAnalyser::visit(ArrayTypeSpec &ty)
{
  auto elem = dynamic_cast<NamedTypeSpec *>(ty.elem);
  if (elem == nullptr) {
    Visit(*ty.elem);
    ty.type = CreateArray(ty.count, ty.typ.elem->type);
  } else {
    // Array types are only legal for integer types, and have special meaning
    // with a small set of builtins.
    if (elem->name == "string") {
      ty.type = CreateString(ty.count);
    } else if (elem->name == "inet") {
      ty.type = CreateInet(ty.count);
    } else if (elem->name == "buffer") {
      ty.type = CreateBuffer(ty.count);
    } else {
      Visit(*ty.elem);
      if (!ty.elem->type.IsIntTy()) {
        LOG(ERROR, ty.loc, err_) << "only integer array types are permitted";
        ty.type = CreateNone();
      } else {
        ty.type = CreateArray(ty.count, ty.elem->type);
      }
    }
  }
}

static std::optional<SizedType> nameToType(ASTContext &ctx, std::string &name) {
  static std::unordered_map<std::string, SizedType> type_map = {
    { "bool", CreateBool() },
    { "uint8", CreateUInt(8) },
    { "uint16", CreateUInt(16) },
    { "uint32", CreateUInt(32) },
    { "uint64", CreateUInt(64) },
    { "int8", CreateInt(8) },
    { "int16", CreateInt(16) },
    { "int32", CreateInt(32) },
    { "int64", CreateInt(64) },
    { "void", CreateVoid() },
    { "min_t", CreateMin(true) },
    { "max_t", CreateMax(true) },
    { "sum_t", CreateSum(true) },
    { "count_t", CreateCount(true) },
    { "avg_t", CreateAvg(true) },
    { "stats_t", CreateStats(true) },
    { "umin_t", CreateMin(false) },
    { "umax_t", CreateMax(false) },
    { "usum_t", CreateSum(false) },
    { "ucount_t", CreateCount(false) },
    { "uavg_t", CreateAvg(false) },
    { "ustats_t", CreateStats(false) },
    { "timestamp", CreateTimestamp() },
    { "macaddr_t", CreateMacAddress() },
    { "cgroup_path_t", CreateCgroupPath() },
    { "strerror_t", CreateStrerror() },
  };
  if (type_map.find(name) != type_map.end()) {
    return type_map[name];
  } else if (name == "string") {
    return CreateString(0);
  } else if (name == "inet") {
    return CreateInet(0);
  } else if (name == "buffer") {
    return CreateBuffer(0);
  }
  return std::nullopt;
}

void FieldAnalyser::visit(NamedTypeSpec &ty)
{
  auto maybeType = nameToType(ctx, ty.name);
  if (maybeType) {
    ty.type = *maybeType;
  } else {
    ty.type = CreateNone();
  }
}

void FieldAnalyser::visit(StructTypeSpec &ty)
{
  ty.type = CreateRecord(ty.name, std::weak_ptr<Struct>());
  resolve_type(ty.type);
}

void FieldAnalyser::visit(Identifier &identifier)
{
  bpftrace_.btf_set_.insert(identifier.ident);
}

void FieldAnalyser::visit(Builtin &builtin)
{
  std::string builtin_type;
  sized_type_ = CreateNone();
  if (builtin.ident == "ctx") {
    if (!probe_)
      return;
    switch (prog_type_) {
      case libbpf::BPF_PROG_TYPE_KPROBE:
        builtin_type = "struct pt_regs";
        break;
      case libbpf::BPF_PROG_TYPE_PERF_EVENT:
        builtin_type = "struct bpf_perf_event_data";
        break;
      default:
        break;
    }
    // For each iterator probe, the context is pointing to specific struct,
    // make them resolved and available
    if (probe_type_ == ProbeType::iter)
      builtin_type = "struct bpf_iter__" + attach_func_;
  } else if (builtin.ident == "curtask") {
    builtin_type = "struct task_struct";
  } else if (builtin.ident == "args") {
    if (!probe_)
      return;
    resolve_args(*probe_);
    has_builtin_args_ = true;
    return;
  } else if (builtin.ident == "retval") {
    if (!probe_)
      return;
    resolve_args(*probe_);

    auto arg = bpftrace_.structs.GetProbeArg(*probe_, RETVAL_FIELD_NAME);
    if (arg)
      sized_type_ = arg->type;
    return;
  }

  if (bpftrace_.has_btf_data())
    sized_type_ = bpftrace_.btf_->get_stype(builtin_type);
}

void FieldAnalyser::visit(Map &map)
{
  if (map.key_expr)
    Visit(*map.key_expr);

  auto it = var_types_.find(map.ident);
  if (it != var_types_.end())
    sized_type_ = it->second;
}

void FieldAnalyser::visit(Variable &var)
{
  auto it = var_types_.find(var.ident);
  if (it != var_types_.end())
    sized_type_ = it->second;
}

void FieldAnalyser::visit(FieldAccess &acc)
{
  has_builtin_args_ = false;

  Visit(*acc.expr);

  if (has_builtin_args_) {
    auto arg = bpftrace_.structs.GetProbeArg(*probe_, acc.field);
    if (arg)
      sized_type_ = arg->type;

    has_builtin_args_ = false;
  } else if (sized_type_.IsRecordTy()) {
    SizedType field_type = CreateNone();
    if (sized_type_.HasField(acc.field))
      field_type = sized_type_.GetField(acc.field).type;

    if (!field_type.IsNoneTy()) {
      sized_type_ = field_type;
    } else if (bpftrace_.has_btf_data()) {
      // If the struct type or the field type has not been resolved, add the
      // type to the BTF set to let ClangParser resolve it
      bpftrace_.btf_set_.insert(sized_type_.GetName());
      auto field_type_name = bpftrace_.btf_->type_of(sized_type_.GetName(),
                                                     acc.field);
      bpftrace_.btf_set_.insert(field_type_name);
    }
  }
}

void FieldAnalyser::visit(ArrayAccess &arr)
{
  Visit(*arr.indexpr);
  Visit(*arr.expr);
  if (sized_type_.IsPtrTy()) {
    sized_type_ = *sized_type_.GetPointeeTy();
    resolve_fields(sized_type_);
  } else if (sized_type_.IsArrayTy()) {
    sized_type_ = *sized_type_.GetElementTy();
    resolve_fields(sized_type_);
  }
}

void FieldAnalyser::visit(Cast &cast)
{
  Visit(*cast.spec);
  Visit(*cast.expr);
  cast.type = cast.spec->type;
}

static Expression *maybeConvertToTypeSpec(ASTContext& ctx, const Expression *expr)
{
  // If it is an array then it could be a type expression. We check to see if
  // this resolves, and then convert to a suitable type spec.
  if (auto arr = dynamic_cast<ArrayAccess*>(expr)) {
    if ((auto index = dynamic_cast<Integer*>(arr->indexpr)) && !index->is_negative) {
      auto sub = maybeConvertToTypeSpec(expr);
      if (auto ts = dynamic_cast<TypeSpec*>(sub)) {
        return ctx.make_node<ArrayTypeSpec>(ctx_index->n, sub);
      }
    }
  }
  if (auto id = dynamic_cast<Identifier*>(expr)) {
    auto maybeType = nameToType(ctx, id->ident);
    if (maybeType) {
      return ctx.make_node<NamedTypeSpec>(id->ident);
    }
  }
  return expr; // Leave the expression alone.
}

void FieldAnalyser::visit(Sizeof &szof)
{
  // If this is an expression, then we can attempt to convert to a TypeSpec in
  // order to evaluate. This is context-sensitive, so can't be done by the
  // parser directly. This is also true for Offsetof, below.
  szof.expr = maybeConvertToTypeSpec(ctx_, szof.expr);
  Visit(*szof.expr);
  szof.argtype = szof.expr->type;
}

void FieldAnalyser::visit(Offsetof &ofof)
{
  // See above.
  ofof.expr = maybeConvertToTypeSpec(ctx_, szof.expr);
  Visit(*ofof.expr);
  ofof.record = ofof.expr->type;
}

void FieldAnalyser::visit(VarDeclStatement &decl)
{
  if (decl.spec) {
    Visit(*decl.spec);
    decl.var->type = decl.spec->type;
  }
}

void FieldAnalyser::visit(AssignMapStatement &assignment)
{
  Visit(*assignment.map);
  Visit(*assignment.expr);
  var_types_.emplace(assignment.map->ident, sized_type_);
}

void FieldAnalyser::visit(AssignVarStatement &assignment)
{
  Visit(*assignment.expr);
  var_types_.emplace(assignment.var->ident, sized_type_);
}

void FieldAnalyser::visit(Unop &unop)
{
  Visit(*unop.expr);
  if (unop.op == Operator::MUL && sized_type_.IsPtrTy()) {
    sized_type_ = *sized_type_.GetPointeeTy();
    resolve_fields(sized_type_);
  }
}

void FieldAnalyser::resolve_args(Probe &probe)
{
  for (auto *ap : probe.attach_points) {
    // load probe arguments into a special record type "struct <probename>_args"
    Struct probe_args;

    auto probe_type = probetype(ap->provider);
    if (probe_type != ProbeType::fentry && probe_type != ProbeType::fexit &&
        probe_type != ProbeType::uprobe)
      continue;

    if (ap->expansion != ExpansionType::NONE) {
      std::set<std::string> matches;

      // Find all the matches for the wildcard..
      try {
        matches = bpftrace_.probe_matcher_->get_matches_for_ap(*ap);
      } catch (const WildcardException &e) {
        LOG(ERROR) << e.what();
        return;
      }

      // ... and check if they share same arguments.

      Struct ap_args;
      for (auto &match : matches) {
        // Both uprobes and fentry have a target (binary for uprobes, kernel
        // module for fentry).
        std::string func = match;
        std::string target = erase_prefix(func);

        // Trying to attach to multiple fentry. If some of them fails on
        // argument resolution, do not fail hard, just print a warning and
        // continue with other functions.
        if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
          std::string err;
          auto maybe_ap_args = bpftrace_.btf_->resolve_args(
              func, probe_type == ProbeType::fexit, err);
          if (!maybe_ap_args.has_value()) {
            LOG(WARNING) << "fentry:" << ap->func << ": " << err;
            continue;
          }
          ap_args = std::move(*maybe_ap_args);
        } else // uprobe
        {
          Dwarf *dwarf = bpftrace_.get_dwarf(target);
          if (dwarf)
            ap_args = dwarf->resolve_args(func);
          else
            LOG(WARNING, ap->loc, err_) << "No debuginfo found for " << target;
        }

        if (probe_args.size == -1)
          probe_args = ap_args;
        else if (ap_args != probe_args) {
          LOG(ERROR, ap->loc, err_)
              << "Probe has attach points with mixed arguments";
          break;
        }
      }
    } else {
      // Resolving args for an explicit function failed, print an error and fail
      if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit) {
        std::string err;
        auto maybe_probe_args = bpftrace_.btf_->resolve_args(
            ap->func, probe_type == ProbeType::fexit, err);
        if (!maybe_probe_args.has_value()) {
          LOG(ERROR, ap->loc, err_) << "fentry:" << ap->func << ": " << err;
          return;
        }
        probe_args = std::move(*maybe_probe_args);
      } else // uprobe
      {
        Dwarf *dwarf = bpftrace_.get_dwarf(ap->target);
        if (dwarf)
          probe_args = dwarf->resolve_args(ap->func);
        else {
          LOG(WARNING, ap->loc, err_)
              << "No debuginfo found for " << ap->target;
        }
        if (static_cast<int>(probe_args.fields.size()) >
            (arch::max_arg() + 1)) {
          LOG(ERROR, ap->loc, err_) << "\'args\' builtin is not supported for "
                                       "probes with stack-passed arguments.";
        }
      }
    }

    // check if we already stored arguments for this probe
    auto args = bpftrace_.structs.Lookup(probe.args_typename()).lock();
    if (args && *args != probe_args) {
      // we did, and it's different...trigger the error
      LOG(ERROR, ap->loc, err_)
          << "Probe has attach points with mixed arguments";
    } else {
      // store/save args for each ap for later processing
      bpftrace_.structs.Add(probe.args_typename(), std::move(probe_args));
    }
  }
  return;
}

void FieldAnalyser::resolve_fields(SizedType &type)
{
  if (!type.IsRecordTy())
    return;

  if (probe_) {
    for (auto &ap : probe_->attach_points)
      if (Dwarf *dwarf = bpftrace_.get_dwarf(*ap))
        dwarf->resolve_fields(type);
  }

  if (type.GetFieldCount() == 0 && bpftrace_.has_btf_data())
    bpftrace_.btf_->resolve_fields(type);
}

void FieldAnalyser::resolve_type(SizedType &type)
{
  sized_type_ = CreateNone();

  const SizedType *inner_type = &type;
  while (inner_type->IsPtrTy())
    inner_type = inner_type->GetPointeeTy();
  if (!inner_type->IsRecordTy())
    return;
  auto name = inner_type->GetName();

  if (probe_) {
    for (auto &ap : probe_->attach_points)
      if (Dwarf *dwarf = bpftrace_.get_dwarf(*ap))
        sized_type_ = dwarf->get_stype(name);
  }

  if (sized_type_.IsNoneTy() && bpftrace_.has_btf_data())
    sized_type_ = bpftrace_.btf_->get_stype(name);

  // Could not resolve destination type - let ClangParser do it
  if (sized_type_.IsNoneTy())
    bpftrace_.btf_set_.insert(name);
}

void FieldAnalyser::visit(Probe &probe)
{
  probe_ = &probe;

  for (AttachPoint *ap : probe.attach_points) {
    probe_type_ = probetype(ap->provider);
    prog_type_ = progtype(probe_type_);
    attach_func_ = ap->func;
  }
  if (probe.pred) {
    Visit(*probe.pred);
  }
  Visit(*probe.block);
}

void FieldAnalyser::visit(SubprogArg &arg)
{
  Visit(*arg.spec);
}

void FieldAnalyser::visit(Subprog &subprog)
{
  probe_ = nullptr;

  for (SubprogArg *arg : subprog.args) {
    Visit(*arg);
  }
  for (Statement *stmt : subprog.stmts) {
    Visit(*stmt);
  }
  Visit(*subprog.return_type);
}

int FieldAnalyser::analyse()
{
  Visit(*ctx_.root);

  std::string errors = err_.str();
  if (!errors.empty()) {
    out_ << errors;
    return 1;
  }

  return 0;
}

} // namespace bpftrace::ast
