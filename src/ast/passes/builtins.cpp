#include <optional>

#include "arch/arch.h"
#include "ast/passes/builtins.h"
#include "ast/passes/probe_expansion.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

namespace {

class Builtins : public Visitor<Builtins, std::optional<Expression>> {
public:
  explicit Builtins(ASTContext &ast,
                    BPFtrace &bpftrace,
                    const providers::Provider &provider,
                    std::unique_ptr<providers::AttachPoint> &attach_point)
      : ast_(ast),
        bpftrace_(bpftrace),
        provider_(provider),
        attach_point_(attach_point){};

  using Visitor<Builtins, std::optional<Expression>>::visit;
  std::optional<Expression> visit(Builtin &builtin);
  std::optional<Expression> visit(Identifier &identifier);
  std::optional<Expression> visit(Expression &expression);
  std::optional<Expression> check(const std::string &ident, Node &node);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  const providers::Provider &provider_;
  std::unique_ptr<providers::AttachPoint> &attach_point_;
};

} // namespace

static std::string prog_type_name(bpf_prog_type t)
{
  switch (t) {
    case BPF_PROG_TYPE_UNSPEC:
      return "unspec";
    case BPF_PROG_TYPE_SOCKET_FILTER:
      return "socket_filter";
    case BPF_PROG_TYPE_KPROBE:
      return "kprobe";
    case BPF_PROG_TYPE_SCHED_CLS:
      return "sched_cls";
    case BPF_PROG_TYPE_SCHED_ACT:
      return "sched_act";
    case BPF_PROG_TYPE_TRACEPOINT:
      return "tracepoint";
    case BPF_PROG_TYPE_XDP:
      return "xdp";
    case BPF_PROG_TYPE_PERF_EVENT:
      return "perf_event";
    case BPF_PROG_TYPE_CGROUP_SKB:
      return "cgroup_skb";
    case BPF_PROG_TYPE_CGROUP_SOCK:
      return "cgroup_sock";
    case BPF_PROG_TYPE_LWT_IN:
      return "lwt_in";
    case BPF_PROG_TYPE_LWT_OUT:
      return "lwt_out";
    case BPF_PROG_TYPE_LWT_XMIT:
      return "lwt_xmit";
    case BPF_PROG_TYPE_SOCK_OPS:
      return "sock_ops";
    case BPF_PROG_TYPE_SK_SKB:
      return "sk_skb";
    case BPF_PROG_TYPE_CGROUP_DEVICE:
      return "cgroup_device";
    case BPF_PROG_TYPE_SK_MSG:
      return "sk_msg";
    case BPF_PROG_TYPE_RAW_TRACEPOINT:
      return "raw_tracepoint";
    case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
      return "cgroup_sock_addr";
    case BPF_PROG_TYPE_LWT_SEG6LOCAL:
      return "lwt_seg6local";
    case BPF_PROG_TYPE_LIRC_MODE2:
      return "lirc_mode2";
    case BPF_PROG_TYPE_SK_REUSEPORT:
      return "sk_reuseport";
    case BPF_PROG_TYPE_FLOW_DISSECTOR:
      return "flow_dissector";
    case BPF_PROG_TYPE_CGROUP_SYSCTL:
      return "cgroup_sysctl";
    case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
      return "raw_tracepoint_writable";
    case BPF_PROG_TYPE_CGROUP_SOCKOPT:
      return "cgroup_sockopt";
    case BPF_PROG_TYPE_TRACING:
      return "tracing";
    case BPF_PROG_TYPE_STRUCT_OPS:
      return "struct_ops";
    case BPF_PROG_TYPE_EXT:
      return "ext";
    case BPF_PROG_TYPE_LSM:
      return "lsm";
    case BPF_PROG_TYPE_SK_LOOKUP:
      return "sk_lookup";
    case BPF_PROG_TYPE_SYSCALL:
      return "syscall";
    case BPF_PROG_TYPE_NETFILTER:
      return "netfilter";
    default:
      return "unknown";
  }
}

std::optional<Expression> Builtins::check(const std::string &ident, Node &node)
{
  // N.B. this pass *should* include all the compile-time builtins (probe,
  // provider, etc.) but it presently cannot due to the expansion rules. All
  // builtins should be added here once probes are fully-expanded up front.
  //
  // All of these builtins should be directly evaluated and folded and not
  // associated with any code generation. These builtins should be kept to the
  // minimum possible set to support the standard library.
  if (ident == "__builtin_arch") {
    std::stringstream ss;
    ss << bpftrace::arch::current();
    return ast_.make_node<String>(ss.str(), Location(node.loc));
  }
  if (ident == "__builtin_safe_mode") {
    return ast_.make_node<Boolean>(bpftrace_.safe_mode_, Location(node.loc));
  }
  if (ident == "__builtin_probe_type") {
    return ast_.make_node<String>(provider_.name(), Location(node.loc));
  }
  if (ident == "__builtin_attach_point") {
    return ast_.make_node<String>(attach_point_->name(), Location(node.loc));
  }
  if (ident == "__builtin_prog_type") {
    auto prog_type = attach_point_->prog_type();
    return ast_.make_node<String>(prog_type_name(prog_type),
                                  Location(node.loc));
  }
  return std::nullopt;
}

std::optional<Expression> Builtins::visit(Builtin &builtin)
{
  return check(builtin.ident, builtin);
}

std::optional<Expression> Builtins::visit(Identifier &identifier)
{
  return check(identifier.ident, identifier);
}

std::optional<Expression> Builtins::visit(Expression &expression)
{
  auto replacement = visit(expression.value);
  if (replacement) {
    expression.value = replacement->value;
  }
  return std::nullopt;
}

Pass CreateBuiltinsPass()
{
  auto fn =
      [&](ASTContext &ast, BPFtrace &bpftrace, ExpandedAttachPoints &expanded) {
        for (auto &[probe, detail] : expanded.attach_points) {
          auto &[provider, attach_point] = detail;
          Builtins(ast, bpftrace, *provider, attach_point).visit(*probe);
        }
      };

  return Pass::create("Builtins", fn);
};

} // namespace bpftrace::ast
