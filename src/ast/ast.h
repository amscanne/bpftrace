#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "location.hh"
#include "types.h"
#include "usdt.h"
#include "utils.h"

namespace bpftrace {
namespace ast {

class VisitorBase;

#define DEFINE_ACCEPT void accept(VisitorBase &v) override;

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

  virtual void accept(VisitorBase &v) = 0;

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

  // All expression types must define a method that returns their type. Since
  // this type is not necessarily known until after type inferrence, this may
  // be stored internally as a future and resolved automatically. This is
  // returned as a function pointer as a kind of "future", since some types
  // will be dependent on other types. This function is only safe to use while
  // the ASTContext exists, as it may capture references and pointers to the
  // current node and other nodes.
  //
  // The function `valid` should always be called *first*, and will refresh
  // internal state. This state will not change until `valid` is called again.
  class FutureType {
  public:
    using Rval = std::variant<std::string, SizedType>;
    using Fn = std::function<Rval(void)>;
    FutureType(const FutureType&) = delete;
    FutureType& operator=(const FutureType&) = delete;
    bool valid()
    {
      // If this method is already running, then we must be in a recursive type
      // definition. Just bail on this and return an error. This works only if
      // the FutureType objects are bound and saved within the anonymous
      // functions, so be sure to follow this pattern.
      if (running_ == true)
        return "recursive type inferrence; cannot be resolved";
      if (!result_ || std::holds_alternative<std::string>(*result_)) {
	running_= true;
        result_ = fn_();
	running_= false;
      }
      return std::holds_alternative<SizedType>(*result_);
    }
    std::string error()
    {
      return std::get<std::string>(*result_);
    }
    SizedType type()
    {
      auto ty = std::get<SizedType>(*result_);
      return ty;
    }
  private:
    bool running_ = false;
    std::optional<Rval> result_;
    Fn fn_;
    FutureType(Fn fn) : fn_(fn) {}
  };
  virtual FutureType type() const = 0;

  Map *key_for_map = nullptr;
  Map *map = nullptr;      // Only set when this expression is assigned to a map
  Variable *var = nullptr; // Set when this expression is assigned to a variable
  bool is_literal = false;
  bool is_variable = false;
  bool is_map = false;
};
using ExpressionList = std::vector<Expression *>;

class FixedTypeExpression : public Expression {
public:
  FixedTypeExpression(SizedType type, location loc)
      : Expression(loc), type_(type) {};
  FutureType type() const override
  {
    return FutureType(this, [this](void) -> FutureType::Rval { return type_; });
  }

private:
  SizedType type_;
};

class VariableTypeExpression : public Expression {
public:
  VariableTypeExpression(location loc) : Expression(loc) {};
  FutureType type() const override
  {
    return FutureType(this, [this](void) -> FutureType::Rval {
      // This is in the error state; not able to resolve this type until we
      // have call `set_type` on this value.
      if (!type_)
        return "unknown type";
      if (!type_.valid())
        return type_.error();
      return type_.type();
    });
  }
  // This is used to set the type during inference. Note that this should be
  // used for identifiers, calls and other builtins, not for types containing
  // subexpressions. Those should just implement the recursion directly.
  void set_type(FutureType &&type)
  {
    type_ = std::move(type);
  }

private:
  std::optional<FutureType> type_;
};

class Integer : public FixedTypeExpression {
public:
  DEFINE_ACCEPT

  explicit Integer(int64_t n, location loc, bool is_negative = true);

  int64_t n;
  bool is_negative;

private:
  Integer(const Integer &other) = default;
};

class PositionalParameter : public FixedTypeExpression {
public:
  DEFINE_ACCEPT

  explicit PositionalParameter(PositionalParameterType ptype,
                               long n,
                               location loc);

  PositionalParameterType ptype;
  long n;
  bool is_in_str = false;

private:
  PositionalParameter(const PositionalParameter &other) = default;
};

class String : public FixedTypeExpression {
public:
  DEFINE_ACCEPT

  explicit String(const std::string &str, location loc);

  std::string str;

private:
  String(const String &other) = default;
};

class StackMode : public FixedTypeExpression {
public:
  DEFINE_ACCEPT

  explicit StackMode(const std::string &mode, location loc);

  std::string mode;

private:
  StackMode(const StackMode &other) = default;
};

class Identifier : public VariableTypeExpression {
public:
  DEFINE_ACCEPT

  explicit Identifier(const std::string &ident, location loc);

  std::string ident;

private:
  Identifier(const Identifier &other) = default;
};

class Builtin : public VariableTypeExpression {
public:
  DEFINE_ACCEPT

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

class Call : public VariableTypeExpression {
public:
  DEFINE_ACCEPT

  explicit Call(const std::string &func, location loc);
  Call(const std::string &func, ExpressionList &&vargs, location loc);

  std::string func;
  ExpressionList vargs;

private:
  Call(const Call &other) = default;
};

class Sizeof : public FixedTypeExpression {
public:
  DEFINE_ACCEPT

  Sizeof(SizedType type, location loc);
  Sizeof(Expression *expr, location loc);

  std::variant<SizedType, Expression *> arg;

private:
  Sizeof(const Sizeof &other) = default;
};

class Offsetof : public FixedTypeExpression {
public:
  DEFINE_ACCEPT

  Offsetof(SizedType record, std::string &field, location loc);
  Offsetof(Expression *expr, std::string &field, location loc);

  std::variant<SizedType, Expression *> arg;
  std::string field;

private:
  Offsetof(const Offsetof &other) = default;
};

class Map : public VariableTypeExpression {
public:
  DEFINE_ACCEPT

  explicit Map(const std::string &ident, location loc);
  Map(const std::string &ident, Expression &expr, location loc);

  std::string ident;
  Expression *key_expr = nullptr;
  bool skip_key_validation = false;

private:
  Map(const Map &other) = default;
};

class Variable : public VariableTypeExpression {
public:
  DEFINE_ACCEPT

  explicit Variable(const std::string &ident, location loc);

  std::string ident;

private:
  Variable(const Variable &other) = default;
  std::function<SizedType(void)> type_;
};

class Binop : public Expression {
public:
  DEFINE_ACCEPT

  Binop(Expression *left, Operator op, Expression *right, location loc);

  Expression *left = nullptr;
  Expression *right = nullptr;
  Operator op;

  FutureType type() const override;

private:
  Binop(const Binop &other) = default;
};

class Unop : public Expression {
public:
  DEFINE_ACCEPT

  Unop(Operator op, Expression *expr, location loc = location());
  Unop(Operator op,
       Expression *expr,
       bool is_post_op = false,
       location loc = location());

  Expression *expr = nullptr;
  Operator op;
  bool is_post_op;

  FutureType type() const override;

private:
  Unop(const Unop &other) = default;
};

class FieldAccess : public Expression {
public:
  DEFINE_ACCEPT

  FieldAccess(Expression *expr, const std::string &field);
  FieldAccess(Expression *expr, const std::string &field, location loc);
  FieldAccess(Expression *expr, ssize_t index, location loc);

  Expression *expr = nullptr;
  std::string field;
  ssize_t index = -1;

  FutureType type() const override;

private:
  FieldAccess(const FieldAccess &other) = default;
};

class ArrayAccess : public Expression {
public:
  DEFINE_ACCEPT

  ArrayAccess(Expression *expr, Expression *indexpr);
  ArrayAccess(Expression *expr, Expression *indexpr, location loc);

  Expression *expr = nullptr;
  Expression *indexpr = nullptr;

  FutureType type() const override;

private:
  ArrayAccess(const ArrayAccess &other) = default;
};

class Cast : public FixedTypeExpression {
public:
  DEFINE_ACCEPT

  Cast(SizedType type, Expression *expr, location loc);

  Expression *expr = nullptr;

private:
  Cast(const Cast &other) = default;
};

class Tuple : public Expression {
public:
  DEFINE_ACCEPT

  Tuple(ExpressionList &&elems, location loc);

  ExpressionList elems;

  FutureType type() const override;

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

using StatementList = std::vector<Statement *>;

class ExprStatement : public Statement {
public:
  DEFINE_ACCEPT

  explicit ExprStatement(Expression *expr, location loc);

  Expression *expr = nullptr;

private:
  ExprStatement(const ExprStatement &other) = default;
};

class VarDeclStatement : public Statement {
public:
  DEFINE_ACCEPT

  VarDeclStatement(Variable *var, SizedType type, location loc = location());
  VarDeclStatement(Variable *var, location loc = location());

  Variable *var = nullptr;
  bool set_type = false;

private:
  VarDeclStatement(const VarDeclStatement &other) = default;
};

class AssignMapStatement : public Statement {
public:
  DEFINE_ACCEPT

  AssignMapStatement(Map *map, Expression *expr, location loc = location());

  Map *map = nullptr;
  Expression *expr = nullptr;

private:
  AssignMapStatement(const AssignMapStatement &other) = default;
};

class AssignVarStatement : public Statement {
public:
  DEFINE_ACCEPT

  AssignVarStatement(Variable *var,
                     Expression *expr,
                     location loc = location());
  AssignVarStatement(VarDeclStatement *var_decl_stmt,
                     Expression *expr,
                     location loc = location());

  VarDeclStatement *var_decl_stmt = nullptr;
  Variable *var = nullptr;
  Expression *expr = nullptr;

private:
  AssignVarStatement(const AssignVarStatement &other) = default;
};

class AssignConfigVarStatement : public Statement {
public:
  DEFINE_ACCEPT

  AssignConfigVarStatement(const std::string &config_var,
                           Expression *expr,
                           location loc = location());

  std::string config_var;
  Expression *expr = nullptr;

private:
  AssignConfigVarStatement(const AssignConfigVarStatement &other) = default;
};

class Block : public Statement {
public:
  DEFINE_ACCEPT

  Block(StatementList &&stmts);

  StatementList stmts;

private:
  Block(const Block &other) = default;
};

class If : public Statement {
public:
  DEFINE_ACCEPT

  If(Expression *cond, Block *if_block, Block *else_block);

  Expression *cond = nullptr;
  Block *if_block = nullptr;
  Block *else_block = nullptr;

private:
  If(const If &other) = default;
};

class Unroll : public Statement {
public:
  DEFINE_ACCEPT

  Unroll(Expression *expr, Block *block, location loc);

  long int var = 0;
  Expression *expr = nullptr;
  Block *block = nullptr;

private:
  Unroll(const Unroll &other) = default;
};

class Jump : public Statement {
public:
  DEFINE_ACCEPT

  Jump(JumpType ident, Expression *return_value, location loc = location())
      : Statement(loc), ident(ident), return_value(return_value)
  {
  }
  Jump(JumpType ident, location loc = location())
      : Statement(loc), ident(ident), return_value(nullptr)
  {
  }

  JumpType ident = JumpType::INVALID;
  Expression *return_value;

private:
  Jump(const Jump &other) = default;
};

class Predicate : public Node {
public:
  DEFINE_ACCEPT

  explicit Predicate(Expression *expr, location loc);

  Expression *expr = nullptr;

private:
  Predicate(const Predicate &other) = default;
};

class Ternary : public Expression {
public:
  DEFINE_ACCEPT

  Ternary(Expression *cond, Expression *left, Expression *right, location loc);

  Expression *cond = nullptr;
  Expression *left = nullptr;
  Expression *right = nullptr;

  FutureType type() const override;
};

class While : public Statement {
public:
  DEFINE_ACCEPT

  While(Expression *cond, Block *block, location loc)
      : Statement(loc), cond(cond), block(block)
  {
  }

  Expression *cond = nullptr;
  Block *block = nullptr;

private:
  While(const While &other) = default;
};

class For : public Statement {
public:
  DEFINE_ACCEPT

  For(Variable *decl, Expression *expr, StatementList &&stmts, location loc)
      : Statement(loc), decl(decl), expr(expr), stmts(std::move(stmts))
  {
  }

  Variable *decl = nullptr;
  Expression *expr = nullptr;
  StatementList stmts;
  std::optional<SizedType> ctx_type;

private:
  For(const For &other) = default;
};

class Config : public Statement {
public:
  DEFINE_ACCEPT

  Config(StatementList &&stmts) : stmts(std::move(stmts))
  {
  }

  StatementList stmts;

private:
  Config(const Config &other) = default;
};

class AttachPoint : public Node {
public:
  DEFINE_ACCEPT

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
  DEFINE_ACCEPT

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
  DEFINE_ACCEPT

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
  DEFINE_ACCEPT

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
  DEFINE_ACCEPT

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

#undef DEFINE_ACCEPT

} // namespace ast
} // namespace bpftrace
