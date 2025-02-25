#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "ast/diagnostic.h"
#include "ast/node.h"
#include "types.h"
#include "usdt.h"

namespace bpftrace::ast {

class ASTContext;

class Integer;
class PositionalParameter;
class String;
class StackMode;
class Identifier;
class Builtin;
class Call;
class Sizeof;
class Offsetof;
class Map;
class Variable;
class Binop;
class Unop;
class TupleAccess;
class FieldAccess;
class ArrayAccess;
class Cast;
class Tuple;
class Ternary;
class Block;

class Expression : public Variant<Integer,
                                  PositionalParameter,
                                  String,
                                  StackMode,
                                  Identifier,
                                  Builtin,
                                  Call,
                                  Sizeof,
                                  Offsetof,
                                  Map,
                                  Variable,
                                  Binop,
                                  Unop,
                                  TupleAccess,
                                  FieldAccess,
                                  ArrayAccess,
                                  Cast,
                                  Tuple,
                                  Ternary,
                                  Block> {
public:
  Expression() = default;
  Expression(variant_t &&value) : Variant(std::move(value))
  {
    is_literal = is<Integer>() || is<String>() || is<StackMode>();
  }

  // Record whether this is literal is not. In the future this could be
  // statically determined, but for now this is set based on certain positional
  // parameter configurations.
  bool is_literal;

  // All expressions have a type associated with them. This type may be
  // determined by the expression directly. If it is not known, then this will
  // be `NoneType`.
  SizedType type() const;
};
using ExpressionList = std::vector<Expression>;

class Integer : public Node {
public:
  explicit Integer(Diagnostics &d,
                   int64_t n,
                   Location &&loc,
                   bool is_negative = true)
      : Node(d, std::move(loc)), n(n), is_negative(is_negative){};
  SizedType type() const
  {
    if (is_negative) {
      return CreateInt64();
    } else {
      return CreateUInt64();
    }
  }

  int64_t n;
  bool is_negative;
};

class PositionalParameter : public Node {
public:
  explicit PositionalParameter(Diagnostics &d,
                               PositionalParameterType ptype,
                               long n,
                               Location &&loc)
      : Node(d, std::move(loc)), ptype(ptype), n(n){};
  SizedType type() const
  {
    if (is_in_str) {
      return CreateString(1); // FIXME(amscanne): Not size 1.
    } else {
      return CreateInt64();
    }
  }

  PositionalParameterType ptype;
  long n;
  bool is_in_str = false;
};

class String : public Node {
public:
  explicit String(Diagnostics &d, std::string str, Location &&loc)
      : Node(d, std::move(loc)), str(std::move(str)){};
  SizedType type() const
  {
    return CreateString(str.size() + 1);
  }

  std::string str;
};

class StackMode : public Node {
public:
  explicit StackMode(Diagnostics &d, std::string mode, Location &&loc)
      : Node(d, std::move(loc)), mode(std::move(mode)){};
  SizedType type() const;

  std::string mode;
};

class TypedNode : public Node {
public:
  explicit TypedNode(Diagnostics &d, Location &&loc)
      : Node(d, std::move(loc)){};
  SizedType type() const
  {
    return type_;
  }
  void set_type(SizedType &&type)
  {
    type_ = std::move(type);
  }

private:
  SizedType type_ = CreateNone();
};

class Identifier : public TypedNode {
public:
  explicit Identifier(Diagnostics &d, std::string ident, Location &&loc)
      : TypedNode(d, std::move(loc)), ident(std::move(ident)){};

  const std::string ident;
};

class Builtin : public TypedNode {
public:
  explicit Builtin(Diagnostics &d, std::string ident, Location &&loc)
      : TypedNode(d, std::move(loc)), ident(std::move(ident)){};

  std::string ident;
  int probe_id;

  // Check if the builtin is 'arg0' - 'arg9'
  bool is_argx() const
  {
    return !ident.compare(0, 3, "arg") && ident.size() == 4 &&
           ident.at(3) >= '0' && ident.at(3) <= '9';
  }
};

class Call : public TypedNode {
public:
  explicit Call(Diagnostics &d,
                std::string func,
                ExpressionList &&vargs,
                Location &&loc)
      : TypedNode(d, std::move(loc)),
        func(std::move(func)),
        vargs(std::move(vargs)){};

  std::string func;
  ExpressionList vargs;
};

class Sizeof : public Node {
public:
  explicit Sizeof(Diagnostics &d, SizedType type, Location &&loc)
      : Node(d, std::move(loc)),
        expr(std::in_place_index<0>, std::move(type)){};
  explicit Sizeof(Diagnostics &d, Expression expr, Location &&loc)
      : Node(d, std::move(loc)),
        expr(std::in_place_index<1>, std::move(expr)){};
  SizedType type() const
  {
    return CreateInt64();
  }

  std::variant<SizedType, Expression> expr;
};

class Offsetof : public Node {
public:
  explicit Offsetof(Diagnostics &d,
                    SizedType record,
                    std::vector<std::string> &&field,
                    Location &&loc)
      : Node(d, std::move(loc)), expr(record), field(std::move(field)){};
  explicit Offsetof(Diagnostics &d,
                    Expression expr,
                    std::vector<std::string> &&field,
                    Location &&loc)
      : Node(d, std::move(loc)),
        expr(std::move(expr)),
        field(std::move(field)){};
  SizedType type() const
  {
    return CreateInt64();
  }

  std::variant<SizedType, Expression> expr;
  std::vector<std::string> field;
};

class MapDecl : public Node {
public:
  explicit MapDecl(Diagnostics &d,
                   std::string ident,
                   std::string bpf_type,
                   int max_entries,
                   Location &&loc)
      : Node(d, std::move(loc)),
        ident(std::move(ident)),
        bpf_type(std::move(bpf_type)),
        max_entries(max_entries){};

  std::string ident;
  std::string bpf_type;
  int max_entries;
};

using MapDeclList = std::vector<std::reference_wrapper<MapDecl>>;

class Map : public TypedNode {
public:
  explicit Map(Diagnostics &d, std::string ident, Location &&loc)
      : TypedNode(d, std::move(loc)), ident(std::move(ident)){};
  explicit Map(Diagnostics &d,
               std::string ident,
               Expression key_expr,
               Location &&loc)
      : TypedNode(d, std::move(loc)),
        ident(std::move(ident)),
        key_expr(std::move(key_expr)){};

  std::string ident;
  std::optional<Expression> key_expr;
  SizedType key_type;
  bool skip_key_validation = false;
  // This is for a feature check on reading per-cpu maps
  // which involve calling map_lookup_percpu_elem
  // https://github.com/bpftrace/bpftrace/issues/3755
  bool is_read = true;
};

class Variable : public TypedNode {
public:
  explicit Variable(Diagnostics &d, std::string ident, Location &&loc)
      : TypedNode(d, std::move(loc)), ident(std::move(ident)){};

  std::string ident;
};

enum class Operator {
  INVALID = 0,
  ASSIGN,
  EQ,
  NE,
  LE,
  GE,
  LEFT,
  RIGHT,
  LT,
  GT,
  LAND,
  LOR,
  PLUS,
  INCREMENT,
  DECREMENT,
  MINUS,
  MUL,
  DIV,
  MOD,
  BAND,
  BOR,
  BXOR,
  LNOT,
  BNOT,
};

class Binop : public TypedNode {
public:
  explicit Binop(Diagnostics &d,
                 Expression left,
                 Operator op,
                 Expression right,
                 Location &&loc)
      : TypedNode(d, std::move(loc)),
        left(std::move(left)),
        right(std::move(right)),
        op(op){};

  Expression left;
  Expression right;
  Operator op;
};

class Unop : public TypedNode {
public:
  explicit Unop(Diagnostics &d,
                Operator op,
                Expression expr,
                bool is_post_op,
                Location &&loc)
      : TypedNode(d, std::move(loc)),
        expr(std::move(expr)),
        op(op),
        is_post_op(is_post_op){};

  Expression expr;
  Operator op;
  bool is_post_op;
};

class FieldAccess : public TypedNode {
public:
  explicit FieldAccess(Diagnostics &d,
                       Expression expr,
                       std::string field,
                       Location &&loc)
      : TypedNode(d, std::move(loc)),
        expr(std::move(expr)),
        field(std::move(field))
  {
  }

  Expression expr;
  std::string field;
};

class TupleAccess : public TypedNode {
public:
  explicit TupleAccess(Diagnostics &d,
                       Expression expr,
                       ssize_t index,
                       Location &&loc)
      : TypedNode(d, std::move(loc)), expr(std::move(expr)), index(index)
  {
  }

  Expression expr;
  ssize_t index;
};

class ArrayAccess : public TypedNode {
public:
  explicit ArrayAccess(Diagnostics &d,
                       Expression expr,
                       Expression indexpr,
                       Location &&loc)
      : TypedNode(d, std::move(loc)),
        expr(std::move(expr)),
        indexpr(std::move(indexpr)){};

  Expression expr;
  Expression indexpr;
};

class Cast : public Node {
public:
  explicit Cast(Diagnostics &d, SizedType type, Expression expr, Location &&loc)
      : Node(d, std::move(loc)),
        cast_type(std::move(type)),
        expr(std::move(expr)){};
  SizedType type() const
  {
    return cast_type;
  }

  SizedType cast_type;
  Expression expr;
};

class Tuple : public TypedNode {
public:
  explicit Tuple(Diagnostics &d, ExpressionList &&elems, Location &&loc)
      : TypedNode(d, std::move(loc)), elems(std::move(elems)){};

  ExpressionList elems;
};

class ExprStatement;
class VarDeclStatement;
class AssignMapStatement;
class AssignVarStatement;
class AssignConfigVarStatement;
class Block;
class If;
class Unroll;
class Jump;
class While;
class For;
class Config;

class Statement : public Variant<ExprStatement,
                                 VarDeclStatement,
                                 AssignMapStatement,
                                 AssignVarStatement,
                                 AssignConfigVarStatement,
                                 Block,
                                 If,
                                 Unroll,
                                 Jump,
                                 While,
                                 For,
                                 Config> {
public:
  Statement() = default;
  Statement(variant_t &&value) : Variant(std::move(value)){};
};
using StatementList = std::vector<Statement>;

class ExprStatement : public Node {
public:
  explicit ExprStatement(Diagnostics &d, Expression expr, Location &&loc)
      : Node(d, std::move(loc)), expr(std::move(expr)){};

  Expression expr;
};

class VarDeclStatement : public Node {
public:
  explicit VarDeclStatement(Diagnostics &d,
                            Variable &var,
                            SizedType type,
                            Location &&loc)
      : Node(d, std::move(loc)), var(var), type(std::move(type)){};
  explicit VarDeclStatement(Diagnostics &d, Variable &var, Location &&loc)
      : Node(d, std::move(loc)), var(var){};

  Variable &var;
  std::optional<SizedType> type;
};

class AssignMapStatement : public Node {
public:
  explicit AssignMapStatement(Diagnostics &d,
                              Map &map,
                              Expression expr,
                              Location &&loc)
      : Node(d, std::move(loc)), map(map), expr(std::move(expr)){};

  Map &map;
  Expression expr;
};

class AssignVarStatement : public Node {
public:
  explicit AssignVarStatement(Diagnostics &d,
                              Variable &var,
                              Expression expr,
                              Location &&loc)
      : Node(d, std::move(loc)), var(var), expr(std::move(expr)){};
  explicit AssignVarStatement(Diagnostics &d,
                              VarDeclStatement &var_decl_stmt,
                              Expression expr,
                              Location &&loc)
      : Node(d, std::move(loc)),
        var_decl_stmt(var_decl_stmt),
        var(var_decl_stmt.var),
        expr(std::move(expr)){};

  std::optional<std::reference_wrapper<VarDeclStatement>> var_decl_stmt;
  Variable &var;
  Expression expr;
};

class AssignConfigVarStatement : public Node {
public:
  explicit AssignConfigVarStatement(Diagnostics &d,
                                    std::string config_var,
                                    Expression expr,
                                    Location &&loc)
      : Node(d, std::move(loc)),
        config_var(std::move(config_var)),
        expr(std::move(expr)){};

  std::string config_var;
  Expression expr;
};

class Block : public Node {
public:
  explicit Block(Diagnostics &d, StatementList &&stmts, Location &&loc)
      : Node(d, std::move(loc)), stmts(std::move(stmts)), expr(std::nullopt){};
  explicit Block(Diagnostics &d,
                 StatementList &&stmts,
                 Expression expr,
                 Location &&loc)
      : Node(d, std::move(loc)), stmts(std::move(stmts)), expr(expr){};

  StatementList stmts;
  std::optional<Expression> expr;

  SizedType type() const
  {
    if (expr) {
      return expr->type();
    }
    return CreateNone();
  }
};

class If : public Node {
public:
  explicit If(Diagnostics &d,
              Expression cond,
              Block &if_block,
              Block &else_block,
              Location &&loc)
      : Node(d, std::move(loc)),
        cond(cond),
        if_block(if_block),
        else_block(std::ref(else_block)){};

  Expression cond;
  Block &if_block;
  Block &else_block;
};

class Unroll : public Node {
public:
  explicit Unroll(Diagnostics &d, Expression expr, Block &block, Location &&loc)
      : Node(d, std::move(loc)), expr(std::move(expr)), block(block){};

  long int var = 0;
  Expression expr;
  Block &block;
};

enum class JumpType {
  INVALID = 0,
  RETURN,
  CONTINUE,
  BREAK,
};

class Jump : public Node {
public:
  explicit Jump(Diagnostics &d,
                JumpType ident,
                Expression return_value,
                Location &&loc)
      : Node(d, std::move(loc)),
        ident(ident),
        return_value(std::move(return_value)){};
  explicit Jump(Diagnostics &d, JumpType ident, Location &&loc)
      : Node(d, std::move(loc)), ident(ident){};

  JumpType ident;
  std::optional<Expression> return_value;
};

class Predicate : public Node {
public:
  explicit Predicate(Diagnostics &d, Expression expr, Location &&loc)
      : Node(d, std::move(loc)), expr(std::move(expr)){};

  Expression expr;
};

class Ternary : public TypedNode {
public:
  explicit Ternary(Diagnostics &d,
                   Expression cond,
                   Expression left,
                   Expression right,
                   Location &&loc)
      : TypedNode(d, std::move(loc)),
        cond(std::move(cond)),
        left(std::move(left)),
        right(std::move(right)){};

  Expression cond;
  Expression left;
  Expression right;
};

class While : public Node {
public:
  explicit While(Diagnostics &d, Expression cond, Block &block, Location &&loc)
      : Node(d, std::move(loc)), cond(std::move(cond)), block(block){};

  Expression cond;
  Block &block;
};

class For : public Node {
public:
  explicit For(Diagnostics &d,
               Variable &decl,
               Expression expr,
               StatementList &&stmts,
               Location &&loc)
      : Node(d, std::move(loc)),
        decl(decl),
        expr(expr),
        stmts(std::move(stmts)){};

  Variable &decl;
  Expression expr;
  StatementList stmts;
  SizedType ctx_type;
};

class Config : public Node {
public:
  explicit Config(Diagnostics &d, StatementList &&stmts, Location &&loc)
      : Node(d, std::move(loc)), stmts(std::move(stmts)){};

  StatementList stmts;
};

// There are 2 kinds of attach point expansion:
// - full expansion  - separate LLVM function is generated for each match
// - multi expansion - one LLVM function and BPF program is generated for all
//                     matches, the list of expanded functions is attached to
//                     the BPF program using the k(u)probe.multi mechanism
// - session expansion - extension of the multi expansion when a single BPF
//                       program is shared for both the entry and the exit probe
//                       (when they are both attached to the same attach points)
//                       using the kprobe.session mechanism
enum class ExpansionType {
  NONE,
  FULL,
  MULTI,
  SESSION,
};

class AttachPoint : public Node {
public:
  explicit AttachPoint(Diagnostics &d,
                       std::string raw_input,
                       bool ignore_invalid,
                       Location &&loc)
      : Node(d, std::move(loc)),
        raw_input(std::move(raw_input)),
        ignore_invalid(ignore_invalid){};

  // Currently, the AST node itself is used to store metadata related to probe
  // expansion and attachment. This is done through `create_expansion_copy`
  // below.  Since the nodes are not currently copyable by default (this is
  // currently fraught, as nodes may have backreferences that are not updated
  // in these cases), these fields are copied manually. *Until this is fixed,
  // if you are adding new fields, be sure to update `create_expansion_copy`.

  // Raw, unparsed input from user, eg. kprobe:vfs_read
  std::string raw_input;

  std::string provider;
  std::string target;
  std::string lang; // for userspace probes, enable language-specific features
  std::string ns;
  std::string func;
  std::string pin;
  usdt_probe_entry usdt; // resolved USDT entry, used to support arguments with
                         // wildcard matches
  int64_t freq = 0;
  uint64_t len = 0;   // for watchpoint probes, the width of watched addr
  std::string mode;   // for watchpoint probes, the watch mode
  bool async = false; // for watchpoint probes, if it's an async watchpoint

  ExpansionType expansion = ExpansionType::NONE;
  std::optional<std::reference_wrapper<Probe>> ret_probe; // for session probes

  uint64_t address = 0;
  uint64_t func_offset = 0;
  bool ignore_invalid = false;

  std::string name() const;

  AttachPoint &create_expansion_copy(ASTContext &ctx,
                                     const std::string &match) const;

  int index() const;
  void set_index(int index);

private:
  int index_ = 0;
};
using AttachPointList = std::vector<std::reference_wrapper<AttachPoint>>;

class Probe : public Node {
public:
  explicit Probe(Diagnostics &d,
                 AttachPointList &&attach_points,
                 std::optional<std::reference_wrapper<Predicate>> pred,
                 Block &block,
                 Location &&loc)
      : Node(d, std::move(loc)),
        attach_points(std::move(attach_points)),
        pred(pred),
        block(block){};

  AttachPointList attach_points;
  std::optional<std::reference_wrapper<Predicate>> pred;
  Block &block;

  std::string name() const;
  std::string args_typename() const;
  bool need_expansion = false;    // must build a BPF program per wildcard match
  int tp_args_structs_level = -1; // number of levels of structs that must
                                  // be imported/resolved for tracepoints

  int index() const;
  void set_index(int index);

  bool has_ap_of_probetype(ProbeType probe_type);

private:
  int index_ = 0;
};
using ProbeList = std::vector<std::reference_wrapper<Probe>>;

class SubprogArg : public Node {
public:
  explicit SubprogArg(Diagnostics &d,
                      std::string name,
                      SizedType type,
                      Location &&loc)
      : Node(d, std::move(loc)), name(std::move(name)), type(std::move(type)){};

  const std::string name;
  SizedType type;
};
using SubprogArgList = std::vector<std::reference_wrapper<SubprogArg>>;

class Subprog : public Node {
public:
  Subprog(Diagnostics &d,
          std::string name,
          SubprogArgList &&args,
          SizedType return_type,
          StatementList &&stmts,
          Location &&loc)
      : Node(d, std::move(loc)),
        name(std::move(name)),
        args(std::move(args)),
        return_type(std::move(return_type)),
        stmts(std::move(stmts)){};

  const std::string name;
  SubprogArgList args;
  SizedType return_type;
  StatementList stmts;
};
using SubprogList = std::vector<std::reference_wrapper<Subprog>>;

// The full program is not itself a node, rather it holds all the various
// pieces of a complete program.
class Program {
public:
  std::string c_definitions;
  std::optional<std::reference_wrapper<Config>> config;
  SubprogList functions;
  ProbeList probes;
  MapDeclList map_decls;

  // reset will clear all elements.
  void reset()
  {
    c_definitions.clear();
    config.reset();
    functions.clear();
    probes.clear();
    map_decls.clear();
  }
};

std::string opstr(const Binop &binop);
std::string opstr(const Unop &unop);
std::string opstr(const Jump &jump);

SizedType ident_to_record(const std::string &ident, int pointer_level = 0);
SizedType ident_to_sized_type(const std::string &ident);

} // namespace bpftrace::ast
