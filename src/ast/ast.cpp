#include "ast/ast.h"

#include <algorithm>

#include "ast/visitors.h"
#include "log.h"

namespace bpftrace::ast {

#define MAKE_ACCEPT(Ty)                                                        \
  void Ty::accept(VisitorBase &v)                                              \
  {                                                                            \
    v.visit(*this);                                                            \
  };

MAKE_ACCEPT(Integer)
MAKE_ACCEPT(String)
MAKE_ACCEPT(StackMode)
MAKE_ACCEPT(Builtin)
MAKE_ACCEPT(Identifier)
MAKE_ACCEPT(PositionalParameter)
MAKE_ACCEPT(Call)
MAKE_ACCEPT(Sizeof)
MAKE_ACCEPT(Offsetof)
MAKE_ACCEPT(Map)
MAKE_ACCEPT(Variable)
MAKE_ACCEPT(Binop)
MAKE_ACCEPT(Unop)
MAKE_ACCEPT(Ternary)
MAKE_ACCEPT(FieldAccess)
MAKE_ACCEPT(ArrayAccess)
MAKE_ACCEPT(Cast)
MAKE_ACCEPT(Tuple)
MAKE_ACCEPT(ExprStatement)
MAKE_ACCEPT(AssignMapStatement)
MAKE_ACCEPT(AssignVarStatement)
MAKE_ACCEPT(AssignConfigVarStatement)
MAKE_ACCEPT(VarDeclStatement)
MAKE_ACCEPT(Predicate)
MAKE_ACCEPT(AttachPoint)
MAKE_ACCEPT(If)
MAKE_ACCEPT(Unroll)
MAKE_ACCEPT(While)
MAKE_ACCEPT(For)
MAKE_ACCEPT(Config)
MAKE_ACCEPT(Block)
MAKE_ACCEPT(Jump)
MAKE_ACCEPT(Probe)
MAKE_ACCEPT(SubprogArg)
MAKE_ACCEPT(Subprog)
MAKE_ACCEPT(Program)

#undef MAKE_ACCEPT

Integer::Integer(int64_t n, location loc, bool is_negative)
    : Expression(loc), n(n), is_negative(is_negative)
{
  is_literal = true;
}

String::String(const std::string &str, location loc)
    : Expression(loc), str(str), type_(CreateString(str.size() + 1))
{
  is_literal = true;
}

StackMode::StackMode(const std::string &mode, location loc)
    : Expression(loc), mode(mode)
{
  is_literal = true;

  // Parse the mode and create the fixed type here.
  auto stack_mode = bpftrace::Config::get_stack_mode(mode.mode);
  if (stack_mode.has_value()) {
    auto t = CreateStackMode();
    t.stack_type.mode = stack_mode.value();
    type_ = FixedType(t);
  } else {
    LOG(ERROR, mode.loc, err_) << "Unknown stack mode: '" + mode.mode + "'";
  }
}

Builtin::Builtin(const std::string &ident, location loc)
    : Expression(loc), ident(is_deprecated(ident))
{
}

Identifier::Identifier(const std::string &ident, location loc)
    : Expression(loc), ident(ident)
{
}

PositionalParameter::PositionalParameter(PositionalParameterType ptype,
                                         long n,
                                         location loc)
    : Expression(loc), ptype(ptype), n(n)
{
  is_literal = true;
}

Call::Call(const std::string &func, location loc)
    : Expression(loc), func(is_deprecated(func))
{
}

Call::Call(const std::string &func, ExpressionList &&vargs, location loc)
    : Expression(loc), func(is_deprecated(func)), vargs(std::move(vargs))
{
}

Sizeof::Sizeof(SizedType type, location loc) : Expression(loc), argtype(type)
{
}

Sizeof::Sizeof(Expression *expr, location loc) : Expression(loc), expr(expr)
{
}

Offsetof::Offsetof(SizedType record, std::string &field, location loc)
    : Expression(loc), record(record), field(field)
{
}

Offsetof::Offsetof(Expression *expr, std::string &field, location loc)
    : Expression(loc), expr(expr), field(field)
{
}

Map::Map(const std::string &ident, location loc) : Expression(loc), ident(ident)
{
  is_map = true;
}

Map::Map(const std::string &ident, Expression &expr, location loc)
    : Expression(loc), ident(ident), key_expr(&expr)
{
  is_map = true;
  key_expr->key_for_map = this;
}

Variable::Variable(const std::string &ident, location loc)
    : Expression(loc), ident(ident)
{
  is_variable = true;
}

Binop::Binop(Expression *left, Operator op, Expression *right, location loc)
    : Expression(loc), left(left), right(right), op(op)
{
}

FutureType Binop::type()
{
  return FutureType([leftType = left->type(), rightRight = right->type()] -> FutureType::Rval {
    if (!leftType.valid()) {
      return leftType.error();
    }
    if (!rightType.valid()) {
      return rightType.error();
    }
    auto lht = leftType.type();
    auto rht = rightType.type();
    std::streamstring ss;
    if (lht.IsArrayTy() && rht.IsArrayTy()) {
      if (op != Operator::EQ && op != Operator::NE) {
        ss << "The " << opstr(binop) << " operator cannot be used on arrays.";
	return ss.str();
      }
      if (!lht.GetElementTy()->IsIntegerTy() || lht != rht) {
        ss << "Only arrays of same sized integer support comparison operators.";
	return ss.str();
	}
      if (lht.GetNumElements() != rht.GetNumElements()) {
        ss << "Only arrays of same size support comparison operators.";
	return ss.str();
      }
    }
  });
}

Unop::Unop(Operator op, Expression *expr, location loc)
    : Expression(loc), expr(expr), op(op), is_post_op(false)
{
}

Unop::Unop(Operator op, Expression *expr, bool is_post_op, location loc)
    : Expression(loc), expr(expr), op(op), is_post_op(is_post_op)
{
}

FutureType Unop::type()
{
  // The type for most unary operators stays the same, but in some cases it
  // will change to be the element type, or just the logical result. These are
  // unpacked in the type resolution path.
  return FutureType(this, [op, exprType = expr->type()] -> FutureType::Rval {
    if (!exprType.valid())
      return exprType.error();
    switch (op) {
      case LNOT:
        return CreateInt(1);
      case MUL: {
        auto t = exprType.type();
        if (!t.IsPtrTy()) {
          std::stringstream ss;
          ss << "invalid dereference of type " << t;
          return ss.str();
        }
        return t.GetPointeeTy();
      }
      default:
        return exprType.type();
    }
  });
}

Ternary::Ternary(Expression *cond,
                 Expression *left,
                 Expression *right,
                 location loc)
    : Expression(loc), cond(cond), left(left), right(right)
{
}

FutureType Ternary::type()
{
  // The type of the ternary is defined if the types of the left and right
  // expressions are the same. In this case, we return the type, otherwise we
  // return an invalid type.
  return FutureType(this, [leftType = left->type(), rightRight = right->type()] -> FutureType::Rval {
    if (!leftType.valid())
      return leftType.error();
    if (!rightType.valid())
      return rightType.error();
    auto lt = leftType.type();
    auto rt = rightType.type();
    if (lt != rt) {
      std::stringstream ss;
      ss << "ternary type mismatch, left type is " << lt << ", right type is "
         << rt;
      return ss.str();
    }
    return lt;
  });
}

FieldAccess::FieldAccess(Expression *expr,
                         const std::string &field,
                         location loc)
    : Expression(loc), expr(expr), field(field)
{
}

FieldAccess::FieldAccess(Expression *expr, ssize_t index, location loc)
    : Expression(loc), expr(expr), index(index)
{
}

FutureType FieldAccess::type()
{
  return FutureType([exprType = expr->type(), field] -> FutureType::Rval {
    if (!exprType.valid())
      return exprType.error();
    auto t = exprType.type();
    if (!t.IsRecordTy()) {
      std::stringstream ss;
      ss << "field access on non-record type " << t;
      return ss.str();
    }
    if (t.HasField(field)) {
      std::stringstream ss;
      ss << "field " << field << "not found on type " << t;
      return ss.str();
    }
    return t.GetField(field).type;
  });
}

ArrayAccess::ArrayAccess(Expression *expr, Expression *indexpr, location loc)
    : Expression(loc), expr(expr), indexpr(indexpr)
{
}

FutureType ArrayAccess::type()
{
  return FutureType([exprType = expr->type()] -> FutureType::Rval {
    if (!exprType.valid())
      return exprType.error();
    auto t = exprType.type();
    if (t.IsArrayTy()) {
      return t.GetElementTy();
    }
    if (t.IsPointerTy()) {
      return t.GetPointeeTy();
    }
    std::stringstream ss;
    ss << "type " << t << " not legal for array access";
    return ss.str();
  });
}

Cast::Cast(SizedType cast_type, Expression *expr, location loc)
    : FixedTypeExpression(cast_type, loc), expr(expr)
{
}

Tuple::Tuple(ExpressionList &&elems, location loc)
    : Expression(loc), elems(std::move(elems))
{
}

FutureType Tuple::type()
{
  return FutureType(this, [this] -> FutureType::Rval {
    std::vector<SizedType> types;
    for (auto expr : elems) {
      auto exprType = expr->type();
      if (!exprType.valid())
        return exprType.error();
      auto t = exprType.type();
      if (t.IsMultiOutputMapTy()) {
        std::stringstream ss;
        ss << "map type " << t << " cannot exist inside a tuple";
        return ss.str();
      }
      types.push_back(t);
    }
    return Struct::CreateTuple(elements);
  });
}

ExprStatement::ExprStatement(Expression *expr, location loc)
    : Statement(loc), expr(expr)
{
}

AssignMapStatement::AssignMapStatement(Map *map, Expression *expr, location loc)
    : Statement(loc), map(map), expr(expr)
{
  expr->map = map;
};

AssignVarStatement::AssignVarStatement(Variable *var,
                                       Expression *expr,
                                       location loc)
    : Statement(loc), var(var), expr(expr)
{
  expr->var = var;
}

AssignVarStatement::AssignVarStatement(VarDeclStatement *var_decl_stmt,
                                       Expression *expr,
                                       location loc)
    : Statement(loc),
      var_decl_stmt(var_decl_stmt),
      var(var_decl_stmt->var),
      expr(expr)
{
  expr->var = var;
}

AssignConfigVarStatement::AssignConfigVarStatement(
    const std::string &config_var,
    Expression *expr,
    location loc)
    : Statement(loc), config_var(config_var), expr(expr)
{
}

VarDeclStatement::VarDeclStatement(Variable *var, SizedType type, location loc)
    : Statement(loc), var(var), set_type(true)
{
  var->set_type(std::move(type));
}

VarDeclStatement::VarDeclStatement(Variable *var, location loc)
    : Statement(loc), var(var)
{
}

Predicate::Predicate(Expression *expr, location loc) : Node(loc), expr(expr)
{
}

AttachPoint::AttachPoint(const std::string &raw_input, location loc)
    : Node(loc), raw_input(raw_input)
{
}

Block::Block(StatementList &&stmts) : stmts(std::move(stmts))
{
}

If::If(Expression *cond, Block *if_block, Block *else_block)
    : cond(cond), if_block(if_block), else_block(else_block)
{
}

Unroll::Unroll(Expression *expr, Block *block, location loc)
    : Statement(loc), expr(expr), block(block)
{
}

Probe::Probe(AttachPointList &&attach_points, Predicate *pred, Block *block)
    : attach_points(std::move(attach_points)), pred(pred), block(block)
{
}

SubprogArg::SubprogArg(std::string name, SizedType type)
    : type(std::move(type)), name_(std::move(name))
{
}

std::string SubprogArg::name() const
{
  return name_;
}

Subprog::Subprog(std::string name,
                 SizedType return_type,
                 SubprogArgList &&args,
                 StatementList &&stmts)
    : args(std::move(args)),
      return_type(std::move(return_type)),
      stmts(std::move(stmts)),
      name_(std::move(name))
{
}

Program::Program(const std::string &c_definitions,
                 Config *config,
                 SubprogList &&functions,
                 ProbeList &&probes)
    : c_definitions(c_definitions),
      config(config),
      functions(std::move(functions)),
      probes(std::move(probes))
{
}

std::string opstr(const Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      return "return";
    case JumpType::BREAK:
      return "break";
    case JumpType::CONTINUE:
      return "continue";
    default:
      return {};
  }

  return {}; // unreached
}

std::string opstr(const Binop &binop)
{
  switch (binop.op) {
    case Operator::EQ:
      return "==";
    case Operator::NE:
      return "!=";
    case Operator::LE:
      return "<=";
    case Operator::GE:
      return ">=";
    case Operator::LT:
      return "<";
    case Operator::GT:
      return ">";
    case Operator::LAND:
      return "&&";
    case Operator::LOR:
      return "||";
    case Operator::LEFT:
      return "<<";
    case Operator::RIGHT:
      return ">>";
    case Operator::PLUS:
      return "+";
    case Operator::MINUS:
      return "-";
    case Operator::MUL:
      return "*";
    case Operator::DIV:
      return "/";
    case Operator::MOD:
      return "%";
    case Operator::BAND:
      return "&";
    case Operator::BOR:
      return "|";
    case Operator::BXOR:
      return "^";
    default:
      return {};
  }

  return {}; // unreached
}

std::string opstr(const Unop &unop)
{
  switch (unop.op) {
    case Operator::LNOT:
      return "!";
    case Operator::BNOT:
      return "~";
    case Operator::MINUS:
      return "-";
    case Operator::MUL:
      return "dereference";
    case Operator::INCREMENT:
      if (unop.is_post_op)
        return "++ (post)";
      return "++ (pre)";
    case Operator::DECREMENT:
      if (unop.is_post_op)
        return "-- (post)";
      return "-- (pre)";
    default:
      return {};
  }

  return {}; // unreached
}

AttachPoint AttachPoint::create_expansion_copy(const std::string &match) const
{
  AttachPoint ap = *this; // copy here
  switch (probetype(ap.provider)) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      ap.func = match;
      if (match.find(":") != std::string::npos)
        ap.target = erase_prefix(ap.func);
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
      // Tracepoint, uprobe, and fentry/fexit probes specify both a target
      // (category for tracepoints, binary for uprobes, and kernel module
      // for fentry/fexit and a function name.
      ap.func = match;
      ap.target = erase_prefix(ap.func);
      break;
    case ProbeType::usdt:
      // USDT probes specify a target binary path, a provider, and a function
      // name.
      ap.func = match;
      ap.target = erase_prefix(ap.func);
      ap.ns = erase_prefix(ap.func);
      break;
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
      // Watchpoint probes come with target prefix. Strip the target to get the
      // function
      ap.func = match;
      erase_prefix(ap.func);
      break;
    case ProbeType::rawtracepoint:
      ap.func = match;
      break;
    case ProbeType::software:
    case ProbeType::hardware:
    case ProbeType::interval:
    case ProbeType::profile:
    case ProbeType::special:
    case ProbeType::iter:
    case ProbeType::invalid:
      break;
    default:
      LOG(BUG) << "Unknown probe type";
  }
  return ap;
}

std::string AttachPoint::name() const
{
  std::string n = provider;
  if (target != "")
    n += ":" + target;
  if (lang != "")
    n += ":" + lang;
  if (ns != "")
    n += ":" + ns;
  if (func != "") {
    n += ":" + func;
    if (func_offset != 0)
      n += "+" + std::to_string(func_offset);
  }
  if (address != 0)
    n += ":" + std::to_string(address);
  if (freq != 0)
    n += ":" + std::to_string(freq);
  if (len != 0)
    n += ":" + std::to_string(len);
  if (mode.size())
    n += ":" + mode;
  return n;
}

int AttachPoint::index() const
{
  return index_;
}

void AttachPoint::set_index(int index)
{
  index_ = index;
}

std::string Probe::name() const
{
  std::vector<std::string> ap_names;
  std::transform(attach_points.begin(),
                 attach_points.end(),
                 std::back_inserter(ap_names),
                 [](const AttachPoint *ap) { return ap->name(); });
  return str_join(ap_names, ",");
}

std::string Probe::args_typename() const
{
  return "struct " + name() + "_args";
}

int Probe::index() const
{
  return index_;
}

void Probe::set_index(int index)
{
  index_ = index;
}

std::string Subprog::name() const
{
  return name_;
}

bool Probe::has_ap_of_probetype(ProbeType probe_type)
{
  for (auto *ap : attach_points) {
    if (probetype(ap->provider) == probe_type)
      return true;
  }
  return false;
}

SizedType ident_to_record(const std::string &ident, int pointer_level)
{
  SizedType result = CreateRecord(ident, std::weak_ptr<Struct>());
  for (int i = 0; i < pointer_level; i++)
    result = CreatePointer(result);
  return result;
}

} // namespace bpftrace::ast
