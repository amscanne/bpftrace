#pragma once

#include <ostream>

#include "ast/visitor.h"

namespace bpftrace::ast {

class Printer : public Visitor<Printer> {
public:
  explicit Printer(std::ostream &out, bool with_types = false)
      : out_(out), with_types_(with_types){};

  using Visitor<Printer>::visit;
  void visit(CStatement &cstmt);
  void visit(Integer &integer);
  void visit(NegativeInteger &integer);
  void visit(Boolean &boolean);
  void visit(PositionalParameter &param);
  void visit(PositionalParameterCount &param);
  void visit(String &string);
  void visit(None &none);
  void visit(StackMode &mode);
  void visit(Identifier &identifier);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(Typeof &typeof);
  void visit(Typeinfo &typeinfo);
  void visit(Map &map);
  void visit(MapAddr &map_addr);
  void visit(MapDeclStatement &decl);
  void visit(Variable &var);
  void visit(VariableAddr &var_addr);
  void visit(Binop &binop);
  void visit(Unop &unop);
  void visit(IfExpr &if_expr);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
  void visit(TupleAccess &acc);
  void visit(MapAccess &acc);
  void visit(Cast &cast);
  void visit(Tuple &tuple, bool omit_parens = false);
  void visit(AssignMapStatement &assignment);
  void visit(AssignScalarMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(AssignConfigVarStatement &assignment);
  void visit(VarDeclStatement &decl);
  void visit(Unroll &unroll);
  void visit(While &while_block);
  void visit(Range &range);
  void visit(For &for_loop);
  void visit(Config &config);
  void visit(Jump &jump);
  void visit(AttachPoint &ap);
  void visit(Probe &probe);
  void visit(SubprogArg &arg);
  void visit(Subprog &subprog);
  void visit(Import &imp);
  void visit(Program &program);
  void visit(BlockExpr &block);
  void visit(Comptime &comptime);
  void visit(Statement &stmt);
  void visit(Macro &macro);
  void visit(ExprStatement &stmt);
  void visit(Expression &expr, bool top_level = false);
  void visit(const SizedType &type);

  // Used by helpers.
  void print_meta(const Location &loc,
                  bool top_level = false,
                  size_t min_vspace = 0);
  void emit(const std::string &s);

private:
  std::ostream &out_;
  int depth_ = 0;
  bool with_types_ = false;

  void print_type(const SizedType &ty);
  void print_indent();
};

} // namespace bpftrace::ast
