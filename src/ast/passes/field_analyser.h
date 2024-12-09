#pragma once

#include <iostream>
#include <string>
#include <unordered_set>

#include "ast/visitor.h"
#include "bpftrace.h"

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace {
namespace ast {

class FieldAnalyser : public Visitor<FieldAnalyser> {
public:
  explicit FieldAnalyser(Program &program,
                         BPFtrace &bpftrace,
                         std::ostream &out = std::cerr)
      : program_(program),
        bpftrace_(bpftrace),
        prog_type_(libbpf::BPF_PROG_TYPE_UNSPEC),
        out_(out)
  {
  }

  using Visitor<FieldAnalyser>::visit;
  void visit(Identifier &identifier);
  void visit(Builtin &builtin);
  void visit(Map &map);
  void visit(Variable &var);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
  void visit(Cast &cast);
  void visit(Sizeof &szof);
  void visit(Offsetof &ofof);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(Unop &unop);
  void visit(Probe &probe);
  void visit(Subprog &subprog);

  int analyse();

private:
  void resolve_args(Probe &probe);
  void resolve_fields(SizedType &type);
  void resolve_type(SizedType &type);

  Program &program_;
  ProbeType probe_type_;
  std::string attach_func_;
  SizedType sized_type_;
  BPFtrace &bpftrace_;
  libbpf::bpf_prog_type prog_type_;
  bool has_builtin_args_;
  Probe *probe_;

  std::ostream &out_;
  std::ostringstream err_;

  std::map<std::string, SizedType> var_types_;
};

} // namespace ast
} // namespace bpftrace
