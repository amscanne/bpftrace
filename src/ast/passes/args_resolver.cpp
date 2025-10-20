#include <algorithm>
#include <bpf/bpf.h>
#include <cassert>

#include "ast/passes/args_resolver.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/tracepoint_format_parser.h"
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
  if (arg_name_.empty()) {
    OS << "Could not parse arguments of \"" << probe_name_ << "\": " << detail_;
  } else {
    OS << "Could not parse argument \"" << arg_name_ << "\" of \""
       << probe_name_ << "\": " << detail_;
  }
}

namespace {

// Tracks the resolved arguments and how they should be accessed.
struct ResolvedArgs {
  std::shared_ptr<Struct> args; // May be null, if no types are available.
  bool is_btf;         // true for BTF-based (fentry/fexit/rawtracepoint),
                       // false for register-based (kprobe/uprobe/tracepoint).
                       // If set, then args above must be non-null.
  AddrSpace addrspace; // Address space for the arguments.
};

class ArgsResolver : public Visitor<ArgsResolver, bool> {
public:
  explicit ArgsResolver(ASTContext &ast,
                        BPFtrace &bpftrace,
                        MacroRegistry &registry)
      : ast_(ast), bpftrace_(bpftrace), registry_(registry) {};

  using Visitor<ArgsResolver, bool>::visit;
  bool visit(Builtin &builtin);
  bool visit(Expression &expr);
  bool visit(Probe &probe);

private:
  Result<ResolvedArgs> resolve_args(const AttachPoint &ap);
  Expression rewrite(Node &node, const std::string &field_name);
  Expression rewrite(Node &node, size_t field_index);

  ASTContext &ast_;
  BPFtrace &bpftrace_;
  MacroRegistry &registry_;

  // Probe currently being visited.
  Probe *probe_ = nullptr;
  // Tracks the current resolved args context for rewriting.
  std::optional<ResolvedArgs> current_resolved_args_;
};

} // namespace

bool ArgsResolver::visit(Builtin &builtin)
{
  if (builtin.ident == "args" || builtin.ident == "__builtin_retval" ||
      builtin.argx()) {
    // Have we already resolved?
    if (current_resolved_args_) {
      return true;
    }

    // Everything should be expanded by now.
    assert(probe_ != nullptr);
    if (probe_->attach_points.empty()) {
      return false; // Just ignore this, it will be pruned.
    }
    assert(probe_->attach_points.size() == 1);
    auto *ap = probe_->attach_points.at(0);
    auto result = resolve_args(*ap);
    if (!result) {
      builtin.addError() << result.takeError();
      return false;
    }
    auto resolved = std::move(*result);

    // Add to our structs for use later on.
    if (resolved.args != nullptr) {
      if (auto type_name = probe_->args_typename()) {
        auto copy = resolved.args;
        bpftrace_.structs.Add(*type_name, std::move(copy));
      }
    }

    // Store for later use in rewrite.
    current_resolved_args_ = std::move(resolved);
    return true;
  }

  return false;
}

bool ArgsResolver::visit(Expression &expr)
{
  // Check if this is a FieldAccess that needs rewriting.
  if (auto *field_access = expr.as<FieldAccess>()) {
    // Visit the field access to get the struct definition.
    bool needs_rewrite = visit(field_access->expr);
    if (!needs_rewrite) {
      return false;
    }
    // Rewrite the entire field access using the stored resolution info.
    expr = rewrite(*field_access, field_access->field);
  }

  // Check if this is __builtin_retval that needs rewriting.
  if (auto *builtin = expr.as<Builtin>()) {
    bool needs_rewrite = visit(*builtin);
    if (!needs_rewrite) {
      return false;
    }
    if (auto arg_num = builtin->argx()) {
      // Rewrite to use a simple integer access.
      expr = rewrite(*builtin, *arg_num);
    } else if (builtin->ident == "__builtin_retval") {
      // Look for the special return value field "$retval".
      auto &fields = current_resolved_args_->args->fields;
      auto retval_it = std::ranges::find_if(fields, [](const Field &f) {
        return f.name == "$retval";
      });
      if (retval_it != fields.end()) {
        expr = rewrite(*builtin, retval_it->name);
      }
    } else if (builtin->ident == "args") {
      // So this is *not* a field access on args, but simply args
      // used directly for something else. In these cases, we just
      // replace directly with `ctx`, and let the chips fall where
      // they may. If this is not valid for this context, so be it.
      expr = ast_.make_node<Builtin>(builtin->loc, "ctx");
    }
  }

  // For other expressions, visit normally and propagate struct info. If the
  // expression has just been rewritten, this should always return false.
  return visit(expr.value);
}

Result<ResolvedArgs> ArgsResolver::resolve_args(const AttachPoint &ap)
{
  auto probe_type = probetype(ap.provider);
  switch (probe_type) {
    case ProbeType::fentry:
    case ProbeType::fexit: {
      auto args = bpftrace_.btf_->resolve_args(
          ap.func, probe_type == ProbeType::fexit, true, false);
      if (!args)
        return args.takeError();
      return ResolvedArgs{ .args = std::move(*args),
                           .is_btf = true,
                           .addrspace = AddrSpace::none };
    }
    case ProbeType::rawtracepoint: {
      auto args = bpftrace_.btf_->resolve_raw_tracepoint_args(ap.func);
      if (!args)
        return args.takeError();
      return ResolvedArgs{ .args = std::move(*args),
                           .is_btf = true,
                           .addrspace = AddrSpace::none };
    }
    case ProbeType::tracepoint: {
      TracepointFormatParser parser(ap.target, ap.func, bpftrace_);
      auto ok = parser.parse_format_file();
      if (!ok)
        return ok.takeError();
      auto args = parser.get_tracepoint_struct();
      if (!args)
        return args.takeError();
      // syscalls tracepoints are user space, others are kernel.
      auto addrspace = (ap.target == "syscalls") ? AddrSpace::user
                                                 : AddrSpace::kernel;
      return ResolvedArgs{ .args = std::move(*args),
                           .is_btf = false,
                           .addrspace = addrspace };
    }
    case ProbeType::uprobe:
    case ProbeType::uretprobe: {
      Dwarf *dwarf = bpftrace_.get_dwarf(ap.target);
      if (dwarf) {
        // Register-based, use cast, user address space. Note that limits on the
        // argument count are imposed by the standard library macros, not here.
        auto args = dwarf->resolve_args(ap.func);
        return ResolvedArgs{ .args = args,
                             .is_btf = false,
                             .addrspace = AddrSpace::user };
      }
      // We understand what arguments are, but don't have any debuginfo
      // that we could reasonable interpret to make this leap.
      return ResolvedArgs{ .args = nullptr,
                           .is_btf = false,
                           .addrspace = AddrSpace::user };
    }
    case ProbeType::kprobe:
    case ProbeType::kretprobe: {
      auto args = bpftrace_.btf_->resolve_args(ap.func, false, false, false);
      if (!args) {
        // Allow the arguments to be used, but they will be untyped.
        return ResolvedArgs{ .args = nullptr,
                             .is_btf = false,
                             .addrspace = AddrSpace::kernel };
      }
      // Register-based, use cast, kernel address space.
      return ResolvedArgs{ .args = std::move(*args),
                           .is_btf = false,
                           .addrspace = AddrSpace::kernel };
    }
    default:
      // We don't know how to parse `args.X` for this probe.
      return make_error<ast::ArgParseError>(ap.name(),
                                            "no arguments available");
  }
}

bool ArgsResolver::visit(Probe &probe)
{
  probe_ = &probe;
  current_resolved_args_.reset();
  return visit(*probe.block);
}

Expression ArgsResolver::rewrite(Node &node, const std::string &field_name)
{
  assert(current_resolved_args_);

  // Figure out the field index.
  size_t field_index = 0;
  for (const auto &field : current_resolved_args_->args->fields) {
    if (field.name == field_name) {
      break;
    }
    field_index++;
  }
  // Did we find the field?
  if (field_index >= current_resolved_args_->args->fields.size()) {
    node.addError() << "Unknown field: " << field_name;
    return ast_.make_node<None>(Location(node.loc));
  }

  if (current_resolved_args_->is_btf) {
    // BTF-based: rewrite to ctx.field_name.
    const auto &field_type =
        current_resolved_args_->args->fields.at(field_index).type;
    auto *ctx_ident = ast_.make_node<Builtin>(node.loc, "ctx");
    auto *field_access = ast_.make_node<FieldAccess>(node.loc,
                                                     ctx_ident,
                                                     field_name);
    // Set the field type with address space and ctx access marker.
    auto typed_field = field_type;
    typed_field.SetAS(current_resolved_args_->addrspace);
    field_access->field_type = typed_field;
    return field_access;
  } else {
    // Just transform using the found provided index.
    return rewrite(node, field_index);
  }
}

Expression ArgsResolver::rewrite(Node &node, size_t field_index)
{
  assert(current_resolved_args_);

  // Register-based: rewrite to (field_type)arg(field_index).
  auto *index_arg = ast_.make_node<Integer>(node.loc,
                                            static_cast<uint64_t>(field_index));
  ExpressionList vargs;
  vargs.emplace_back(index_arg);
  auto *call = ast_.make_node<Call>(node.loc, "arg", std::move(vargs));
  auto expr = Expression(call);
  expand_macro(ast_, expr, registry_);

  // If we do have types for these arguments, then we can automatically cast to
  // the suitable type. If this is beyond the number of fields, we just let this
  // be the raw register associated with that conventional argument number.
  if (current_resolved_args_->args &&
      field_index < current_resolved_args_->args->fields.size()) {
    const auto &field_type =
        current_resolved_args_->args->fields.at(field_index).type;
    // Create typeof with the field type that includes address space.
    auto typed_field = field_type;
    typed_field.SetAS(current_resolved_args_->addrspace);
    auto *type_node = ast_.make_node<Typeof>(node.loc, typed_field);

    // Wrap in cast: (field_type)arg(N).
    expr = ast_.make_node<Cast>(node.loc, type_node, call);
  }

  return expr;
}

Pass CreateArgsResolverPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b, MacroRegistry &registry) {
    ArgsResolver resolver(ast, b, registry);
    resolver.visit(ast.root);
  };

  return Pass::create("ArgsResolver", fn);
};

} // namespace bpftrace::ast
