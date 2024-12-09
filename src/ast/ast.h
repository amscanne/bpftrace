#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "location.hh"
#include "types.h"
#include "usdt.h"
#include "utils.h"

namespace bpftrace {
namespace ast {

enum class JumpType {
  INVALID = 0,
  RETURN,
  CONTINUE,
  BREAK,
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

// There are 2 kinds of attach point expansion:
// - full expansion  - separate LLVM function is generated for each match
// - multi expansion - one LLVM function and BPF program is generated for all
//                     matches, the list of expanded functions is attached to
//                     the BPF program using the k(u)probe.multi mechanism
enum class ExpansionType {
  NONE,
  FULL,
  MULTI,
};

class Node {
public:
  Node() = default;
  Node(location loc) : loc(loc){};
  virtual ~Node() = default;

  Node(const Node &) = default;
  Node &operator=(const Node &) = delete;
  Node(Node &&) = delete;
  Node &operator=(Node &&) = delete;

  location loc;
};

class Map;
class Variable;
class Expression : public Node {
public:
  Expression() = default;
  Expression(location loc) : Node(loc){};
  virtual ~Expression() = default;

  Expression(const Expression &) = default;
  Expression &operator=(const Expression &) = delete;
  Expression(Expression &&) = delete;
  Expression &operator=(Expression &&) = delete;

  SizedType type;
  Map *key_for_map = nullptr;
  Map *map = nullptr;      // Only set when this expression is assigned to a map
  Variable *var = nullptr; // Set when this expression is assigned to a variable
  bool is_literal = false;
  bool is_variable = false;
  bool is_map = false;
};

class Integer;
class PositionalParameter;
class String;
class StackMode;
class Identifier;
class Builtin;
class Call;
class Sizeof;
class Offsetof;
class Binop;
class Unop;
class FieldAccess;
class ArrayAccess;
class Cast;
class Tuple;
class Ternary;

using ExpressionVariant = std::variant<Integer *,
                                       PositionalParameter *,
                                       String *,
                                       StackMode *,
                                       Identifier *,
                                       Builtin *,
                                       Call *,
                                       Sizeof *,
                                       Offsetof *,
                                       Map *,
                                       Variable *,
                                       Binop *,
                                       Unop *,
                                       FieldAccess *,
                                       ArrayAccess *,
                                       Cast *,
                                       Tuple *,
                                       Ternary *>;

using ExpressionList = std::vector<ExpressionVariant>;

class Integer : public Expression {
public:
  explicit Integer(int64_t n, location loc, bool is_negative = true);

  int64_t n;
  bool is_negative;

private:
  Integer(const Integer &other) = default;
};

class PositionalParameter : public Expression {
public:
  explicit PositionalParameter(PositionalParameterType ptype,
                               long n,
                               location loc);

  PositionalParameterType ptype;
  long n;
  bool is_in_str = false;

private:
  PositionalParameter(const PositionalParameter &other) = default;
};

class String : public Expression {
public:
  explicit String(const std::string &str, location loc);

  std::string str;

private:
  String(const String &other) = default;
};

class StackMode : public Expression {
public:
  explicit StackMode(const std::string &mode, location loc);

  std::string mode;

private:
  StackMode(const StackMode &other) = default;
};

class Identifier : public Expression {
public:
  explicit Identifier(const std::string &ident, location loc);

  std::string ident;

private:
  Identifier(const Identifier &other) = default;
};

class Builtin : public Expression {
public:
  explicit Builtin(const std::string &ident, location loc);

  std::string ident;
  int probe_id;

  // Check if the builtin is 'arg0' - 'arg9'
  bool is_argx() const
  {
    return !ident.compare(0, 3, "arg") && ident.size() == 4 &&
           ident.at(3) >= '0' && ident.at(3) <= '9';
  }

private:
  Builtin(const Builtin &other) = default;
};

class Call : public Expression {
public:
  explicit Call(const std::string &func, location loc);
  Call(const std::string &func, ExpressionList &&vargs, location loc);

  std::string func;
  ExpressionList vargs;

private:
  Call(const Call &other) = default;
};

class Sizeof : public Expression {
public:
  Sizeof(SizedType type, location loc);
  Sizeof(ExpressionVariant expr, location loc);

  std::optional<ExpressionVariant> expr;
  SizedType argtype;

private:
  Sizeof(const Sizeof &other) = default;
};

class Offsetof : public Expression {
public:
  Offsetof(SizedType record, std::string &field, location loc);
  Offsetof(ExpressionVariant expr, std::string &field, location loc);

  SizedType record;
  std::optional<ExpressionVariant> expr;
  std::string field;

private:
  Offsetof(const Offsetof &other) = default;
};

class Map : public Expression {
public:
  explicit Map(const std::string &ident, location loc);
  Map(const std::string &ident, ExpressionVariant expr, location loc);

  std::string ident;
  std::optional<ExpressionVariant> key_expr;
  SizedType key_type;
  bool skip_key_validation = false;

private:
  Map(const Map &other) = default;
};

class Variable : public Expression {
public:
  explicit Variable(const std::string &ident, location loc);

  std::string ident;

private:
  Variable(const Variable &other) = default;
};

class Binop : public Expression {
public:
  Binop(ExpressionVariant left,
        Operator op,
        ExpressionVariant right,
        location loc);

  ExpressionVariant left;
  ExpressionVariant right;
  Operator op;

private:
  Binop(const Binop &other) = default;
};

class Unop : public Expression {
public:
  Unop(Operator op, ExpressionVariant expr, location loc = location());
  Unop(Operator op,
       ExpressionVariant expr,
       bool is_post_op = false,
       location loc = location());

  ExpressionVariant expr;
  Operator op;
  bool is_post_op;

private:
  Unop(const Unop &other) = default;
};

class FieldAccess : public Expression {
public:
  FieldAccess(ExpressionVariant expr, const std::string &field);
  FieldAccess(ExpressionVariant expr, const std::string &field, location loc);
  FieldAccess(ExpressionVariant expr, ssize_t index, location loc);

  ExpressionVariant expr;
  std::string field;
  ssize_t index = -1;

private:
  FieldAccess(const FieldAccess &other) = default;
};

class ArrayAccess : public Expression {
public:
  ArrayAccess(ExpressionVariant expr, ExpressionVariant indexpr);
  ArrayAccess(ExpressionVariant expr, ExpressionVariant indexpr, location loc);

  ExpressionVariant expr;
  ExpressionVariant indexpr;

private:
  ArrayAccess(const ArrayAccess &other) = default;
};

class Cast : public Expression {
public:
  Cast(SizedType type, ExpressionVariant expr, location loc);

  ExpressionVariant expr;

private:
  Cast(const Cast &other) = default;
};

class Tuple : public Expression {
public:
  Tuple(ExpressionList &&elems, location loc);

  ExpressionList elems;

private:
  Tuple(const Tuple &other) = default;
};

class Statement : public Node {
public:
  Statement() = default;
  Statement(location loc) : Node(loc){};
  virtual ~Statement() = default;

  Statement(const Statement &) = default;
  Statement &operator=(const Statement &) = delete;
  Statement(Statement &&) = delete;
  Statement &operator=(Statement &&) = delete;
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

using StatementVariant = std::variant<ExprStatement *,
                                      VarDeclStatement *,
                                      AssignMapStatement *,
                                      AssignVarStatement *,
                                      AssignConfigVarStatement *,
                                      Block *,
                                      If *,
                                      Unroll *,
                                      Jump *,
                                      While *,
                                      For *,
                                      Config *>;

using StatementList = std::vector<StatementVariant>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(ExpressionVariant expr, location loc);

  ExpressionVariant expr;

private:
  ExprStatement(const ExprStatement &other) = default;
};

class VarDeclStatement : public Statement {
public:
  VarDeclStatement(Variable *var, SizedType type, location loc = location());
  VarDeclStatement(Variable *var, location loc = location());

  Variable *var = nullptr;
  bool set_type = false;

private:
  VarDeclStatement(const VarDeclStatement &other) = default;
};

class AssignMapStatement : public Statement {
public:
  AssignMapStatement(Map *map,
                     ExpressionVariant expr,
                     location loc = location());

  Map *map = nullptr;
  ExpressionVariant expr;

private:
  AssignMapStatement(const AssignMapStatement &other) = default;
};

class AssignVarStatement : public Statement {
public:
  AssignVarStatement(Variable *var,
                     ExpressionVariant expr,
                     location loc = location());
  AssignVarStatement(VarDeclStatement *var_decl_stmt,
                     ExpressionVariant expr,
                     location loc = location());

  VarDeclStatement *var_decl_stmt = nullptr;
  Variable *var = nullptr;
  ExpressionVariant expr;

private:
  AssignVarStatement(const AssignVarStatement &other) = default;
};

class AssignConfigVarStatement : public Statement {
public:
  AssignConfigVarStatement(const std::string &config_var,
                           ExpressionVariant expr,
                           location loc = location());

  std::string config_var;
  ExpressionVariant expr;

private:
  AssignConfigVarStatement(const AssignConfigVarStatement &other) = default;
};

class Block : public Statement {
public:
  Block(StatementList &&stmts);

  StatementList stmts;

private:
  Block(const Block &other) = default;
};

class If : public Statement {
public:
  If(ExpressionVariant cond, Block *if_block, Block *else_block);

  ExpressionVariant cond;
  Block *if_block = nullptr;
  Block *else_block = nullptr;

private:
  If(const If &other) = default;
};

class Unroll : public Statement {
public:
  Unroll(ExpressionVariant expr, Block *block, location loc);

  long int var = 0;
  ExpressionVariant expr;
  Block *block = nullptr;

private:
  Unroll(const Unroll &other) = default;
};

class Jump : public Statement {
public:
  Jump(JumpType ident,
       ExpressionVariant return_value,
       location loc = location())
      : Statement(loc), ident(ident), return_value(return_value)
  {
  }
  Jump(JumpType ident, location loc = location()) : Statement(loc), ident(ident)
  {
  }

  JumpType ident = JumpType::INVALID;
  std::optional<ExpressionVariant> return_value;

private:
  Jump(const Jump &other) = default;
};

class Predicate : public Node {
public:
  explicit Predicate(ExpressionVariant expr, location loc);

  ExpressionVariant expr;

private:
  Predicate(const Predicate &other) = default;
};

class Ternary : public Expression {
public:
  Ternary(ExpressionVariant cond,
          ExpressionVariant left,
          ExpressionVariant right,
          location loc);

  ExpressionVariant cond;
  ExpressionVariant left;
  ExpressionVariant right;
};

class While : public Statement {
public:
  While(ExpressionVariant cond, Block *block, location loc)
      : Statement(loc), cond(cond), block(block)
  {
  }

  ExpressionVariant cond;
  Block *block = nullptr;

private:
  While(const While &other) = default;
};

class For : public Statement {
public:
  For(Variable *decl,
      ExpressionVariant expr,
      StatementList &&stmts,
      location loc)
      : Statement(loc), decl(decl), expr(expr), stmts(std::move(stmts))
  {
  }

  Variable *decl = nullptr;
  ExpressionVariant expr;
  StatementList stmts;
  SizedType ctx_type;

private:
  For(const For &other) = default;
};

class Config : public Statement {
public:
  Config(StatementList &&stmts) : stmts(std::move(stmts))
  {
  }

  StatementList stmts;

private:
  Config(const Config &other) = default;
};

class AttachPoint : public Node {
public:
  explicit AttachPoint(const std::string &raw_input, location loc = location());
  AttachPoint(const std::string &raw_input, bool ignore_invalid)
      : AttachPoint(raw_input)
  {
    this->ignore_invalid = ignore_invalid;
  }

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

  uint64_t address = 0;
  uint64_t func_offset = 0;
  bool ignore_invalid = false;

  std::string name() const;

  AttachPoint create_expansion_copy(const std::string &match) const;

  int index() const;
  void set_index(int index);

private:
  AttachPoint(const AttachPoint &other) = default;

  int index_ = 0;
};
using AttachPointList = std::vector<AttachPoint *>;

class Probe : public Node {
public:
  Probe(AttachPointList &&attach_points, Predicate *pred, Block *block);

  AttachPointList attach_points;
  Predicate *pred = nullptr;
  Block *block = nullptr;

  std::string name() const;
  std::string args_typename() const;
  bool need_expansion = false;    // must build a BPF program per wildcard match
  int tp_args_structs_level = -1; // number of levels of structs that must
                                  // be imported/resolved for tracepoints

  int index() const;
  void set_index(int index);

  bool has_ap_of_probetype(ProbeType probe_type);

private:
  Probe(const Probe &other) = default;
  int index_ = 0;
};
using ProbeList = std::vector<Probe *>;

class SubprogArg : public Node {
public:
  SubprogArg(std::string name, SizedType type);

  std::string name() const;
  SizedType type;

private:
  SubprogArg(const SubprogArg &other) = default;
  std::string name_;
};
using SubprogArgList = std::vector<SubprogArg *>;

class Subprog : public Node {
public:
  Subprog(std::string name,
          SizedType return_type,
          SubprogArgList &&args,
          StatementList &&stmts);

  SubprogArgList args;
  SizedType return_type;
  StatementList stmts;

  std::string name() const;

private:
  Subprog(const Subprog &other) = default;
  std::string name_;
};
using SubprogList = std::vector<Subprog *>;

class Program : public Node {
public:
  Program(const std::string &c_definitions,
          Config *config,
          SubprogList &&functions,
          ProbeList &&probes);

  std::string c_definitions;
  Config *config = nullptr;
  SubprogList functions;
  ProbeList probes;

private:
  Program(const Program &other) = default;
};

std::string opstr(const Binop &binop);
std::string opstr(const Unop &unop);
std::string opstr(const Jump &jump);

SizedType ident_to_record(const std::string &ident, int pointer_level = 0);

template <typename T>
concept NodeType = std::derived_from<T, Node>;

/*
 * Manages the lifetime of AST nodes.
 *
 * Nodes allocated by an ASTContext will be kept alive for the duration of the
 * owning ASTContext object.
 */
class ASTContext {
public:
  Program *root = nullptr;

  /*
   * Creates and returns a pointer to an AST node.
   */
  template <NodeType T, typename... Args>
  T *make_node(Args &&...args)
  {
    auto uniq_ptr = std::make_unique<T>(std::forward<Args>(args)...);
    auto *raw_ptr = uniq_ptr.get();
    nodes_.push_back(std::move(uniq_ptr));
    return raw_ptr;
  }

private:
  std::vector<std::unique_ptr<Node>> nodes_;
};

} // namespace ast
} // namespace bpftrace
