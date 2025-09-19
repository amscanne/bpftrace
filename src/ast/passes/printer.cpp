#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <variant>

#include "ast/ast.h"
#include "ast/passes/printer.h"

namespace bpftrace::ast {

template <typename T>
static Location getloc(const T &t)
{
  if constexpr (std::is_same_v<T, Expression>) {
    return t.node().loc;
  } else {
    return t->loc;
  }
}

template <typename T>
static void foreach(Printer &printer,
                    std::vector<T> &items,
                    bool top_level,
                    const std::string &sep = "")
{
  bool first = true;
  for (auto &item : items) {
    auto loc = getloc(item);
    if (!loc->comments().empty()) {
      printer.print_meta(loc, top_level, first ? 0 : 1);
    } else if (loc->vspace() > 0 && top_level) {
      printer.print_meta(loc, top_level, 0);
    }
    if (first) {
      first = false;
    } else if (!top_level) {
      printer.emit(sep);
    }
    first = false;
    if constexpr (std::is_same_v<T, Expression>) {
      printer.visit(item, top_level);
    } else {
      printer.visit(item);
    }
  }
}

void Printer::visit(CStatement &cstmt)
{
  out_ << cstmt.data << std::endl;
}

void Printer::visit(Integer &integer)
{
  if (integer.original) {
    // This typically means that it has special characters such as separately,
    // suffixes, etc. We preserve these as an esthetic choice.
    out_ << *integer.original;
  } else {
    out_ << integer.value;
  }
}

void Printer::visit(NegativeInteger &integer)
{
  out_ << integer.value;
}

void Printer::visit(Boolean &boolean)
{
  if (boolean.value) {
    out_ << "true";
  } else {
    out_ << "false";
  }
}

void Printer::visit(PositionalParameter &param)
{
  out_ << "$" << param.n;
}

void Printer::visit([[maybe_unused]] PositionalParameterCount &param)
{
  out_ << "$#";
}

static std::string escape(const std::string &s)
{
  std::stringstream ss;
  for (char c : s) {
    int code = static_cast<unsigned char>(c);
    if (std::isprint(code)) {
      if (c == '\\')
        ss << "\\\\";
      else if (c == '"')
        ss << "\\\"";
      else
        ss << c;
    } else {
      if (c == '\n')
        ss << "\\n";
      else if (c == '\t')
        ss << "\\t";
      else if (c == '\r')
        ss << "\\r";
      else
        ss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << code;
    }
  }
  return ss.str();
}

void Printer::visit(String &string)
{
  out_ << "\"" << escape(string.value) << "\"";
}

void Printer::visit([[maybe_unused]] None &none)
{
  // Does not have a syntactic representation.
}

void Printer::visit(Builtin &builtin)
{
  out_ << builtin.ident;
}

void Printer::visit(Identifier &identifier)
{
  out_ << identifier.ident;
}

void Printer::visit(Call &call)
{
  out_ << call.func;
  out_ << "(";
  foreach(*this, call.vargs, false, ", ");
  out_ << ")";
}

void Printer::visit(Sizeof &szof)
{
  out_ << "sizeof(";
  visit(szof.record);
  out_ << ")";
}

void Printer::visit(Offsetof &offof)
{
  out_ << "offsetof(";
  visit(offof.record);
  out_ << ", ";
  bool first = true;
  for (const auto &field : offof.field) {
    if (!first) {
      out_ << ".";
    } else {
      first = false;
    }
    out_ << field;
  }
  out_ << ")";
}

void Printer::visit(Typeof &typeof)
{
  if (std::holds_alternative<Expression>(typeof.record)) {
    out_ << "typeof(";
    visit(typeof.record);
    out_ << ")";
  } else {
    // Prefer the simpler form for direct types.
    out_ << typestr(std::get<SizedType>(typeof.record));
  }
}

void Printer::visit(Typeinfo &typeinfo)
{
  out_ << "typeinfo(";
  visit(typeinfo.typeof);
  out_ << ")";
}

void Printer::visit(MapDeclStatement &decl)
{
  out_ << "let " << decl.ident << " = " << decl.bpf_type << "("
       << decl.max_entries << ");" << std::endl;
}

void Printer::visit(Map &map)
{
  out_ << map.ident;
}

void Printer::visit(MapAddr &map_addr)
{
  out_ << "&" << map_addr.map->ident;
}

void Printer::visit(Variable &var)
{
  out_ << var.ident;
}

void Printer::visit(VariableAddr &var_addr)
{
  out_ << "&" << var_addr.var->ident;
}

void Printer::visit(Binop &binop)
{
  visit(binop.left, false);
  out_ << " " << opstr(binop) << " ";
  visit(binop.right, false);
}

void Printer::visit(Unop &unop)
{
  switch (unop.op) {
    case Operator::LNOT:
      out_ << "!";
      visit(unop.expr, false);
      break;
    case Operator::BNOT:
      out_ << "~";
      visit(unop.expr, false);
      break;
    case Operator::MINUS:
      out_ << "-";
      visit(unop.expr, false);
      break;
    case Operator::MUL:
      out_ << "*";
      visit(unop.expr, false);
      break;
    case Operator::INCREMENT:
      if (unop.is_post_op) {
        visit(unop.expr, false);
        out_ << "++";

        break;
      } else {
        out_ << "++";
        visit(unop.expr, false);
      }
      break;
    case Operator::DECREMENT:
      if (unop.is_post_op) {
        visit(unop.expr, false);
        out_ << "--";

        break;
      } else {
        out_ << "--";
        visit(unop.expr, false);
      }
      break;
    default:
      out_ << "???";
      visit(unop.expr, false);
      break;
  }
}

void Printer::visit(IfExpr &if_expr)
{
  out_ << "if ";
  visit(if_expr.cond, false);
  out_ << " ";
  bool force_block = if_expr.right.is<BlockExpr>() ||
                     if_expr.right.is<IfExpr>();
  if (if_expr.left.is<BlockExpr>()) {
    visit(if_expr.left, false);
    force_block = true;
  } else if (force_block) {
    out_ << "{" << std::endl;
    depth_++;
    print_indent();
    visit(if_expr.left, true);
    out_ << std::endl;
    depth_--;
    print_indent();
    out_ << "}";
  }
  if (if_expr.right.is<BlockExpr>() || if_expr.right.is<IfExpr>()) {
    out_ << " else ";
    visit(if_expr.right, false);
  } else if (!if_expr.right.is<None>()) {
    if (force_block) {
      out_ << " else {" << std::endl;
      depth_++;
      print_indent();
      visit(if_expr.right, true);
      out_ << std::endl;
      depth_--;
      print_indent();
      out_ << "}";
    } else {
      out_ << " else { ";
      visit(if_expr.right, false);
      out_ << " }";
    }
  }
}

void Printer::visit(FieldAccess &acc)
{
  visit(acc.expr, false);
  out_ << "." << acc.field;
}

void Printer::visit(ArrayAccess &arr)
{
  visit(arr.expr, false);
  out_ << "[";
  visit(arr.indexpr, false);
  out_ << "]";
}

void Printer::visit(TupleAccess &acc)
{
  visit(acc.expr, false);
  out_ << "." << acc.index;
}

void Printer::visit(MapAccess &acc)
{
  visit(acc.map);
  out_ << "[";
  visit(acc.key, false);
  out_ << "]";
}

void Printer::visit(Cast &cast)
{
  out_ << "(";
  visit(cast.typeof);
  out_ << ")";
  // Avoid ambiguity: if the expression is a unop, then it needs to be
  // put into parenthesis or it may be ambiguously parsed as a binop.
  if (cast.expr.is<Unop>()) {
    out_ << "(";
    visit(cast.expr, true);
    out_ << ")";
  } else {
    // Binops and others will be automatically parenthesized.
    visit(cast.expr, false);
  }
}

void Printer::visit(Tuple &tuple, bool omit_parens)
{
  if (!omit_parens) {
    out_ << "(";
  }
  for (size_t i = 0; i < tuple.elems.size(); i++) {
    visit(tuple.elems.at(i), false);
    if (i == 0 || i < tuple.elems.size() - 1) {
      out_ << ",";
    }
  }
  if (!omit_parens) {
    out_ << ")";
  }
}

void Printer::visit(AssignScalarMapStatement &assignment)
{
  visit(assignment.map);
  // Is this a compound operator?
  auto *binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<Map>() &&
      binop->left.as<Map>()->ident == assignment.map->ident) {
    out_ << " " << opstr(*binop) << "= ";
    visit(binop->right, true);
  } else {
    out_ << " = ";
    visit(assignment.expr, true);
  }
}

void Printer::visit(AssignMapStatement &assignment)
{
  visit(assignment.map);
  out_ << "[";
  if (auto *tuple = assignment.key.as<Tuple>()) {
    visit(*tuple, true);
  } else {
    visit(assignment.key, true);
  }
  out_ << "]";
  // Is this a compound operator?
  auto *binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<MapAccess>() &&
      binop->left.as<MapAccess>()->map->ident == assignment.map->ident &&
      binop->left.as<MapAccess>()->key.value == assignment.key.value) {
    out_ << " " << opstr(*binop) << "= ";
    visit(binop->right, true);
  } else {
    out_ << " = ";
    visit(assignment.expr, true);
  }
}

void Printer::visit(AssignVarStatement &assignment)
{
  visit(assignment.var_decl);
  // Is this a compound operator?
  auto *binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<Variable>() &&
      binop->left.as<Variable>()->ident == assignment.var()->ident) {
    out_ << " " << opstr(*binop) << "= ";
    visit(binop->right, true);
  } else {
    out_ << " = ";
    visit(assignment.expr, true);
  }
}

void Printer::visit(AssignConfigVarStatement &assignment)
{
  print_indent();
  out_ << assignment.var << " = ";
  std::visit(
      [&](auto &v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, bool>) {
          if (v) {
            out_ << "true";
          } else {
            out_ << "false";
          }
        } else if constexpr (std::is_same_v<T, uint64_t>) {
          out_ << v;
        } else if constexpr (std::is_same_v<T, std::string>) {
          // Prefer to use a naked identifier for the configuration,
          // it is rare that we need actual string paths.
          if (escape(v) == v) {
            out_ << v;
          } else {
            out_ << "\"" << escape(v) << "\"";
          }
        }
      },
      assignment.value);
  out_ << ";" << std::endl;
}

void Printer::visit(VarDeclStatement &decl)
{
  out_ << "let ";
  visit(decl.var);
  if (decl.typeof) {
    out_ << " : ";
    visit(decl.typeof);
  }
}

void Printer::visit(Unroll &unroll)
{
  out_ << "unroll (";
  visit(unroll.expr, true);
  out_ << ") ";
  visit(unroll.block);
}

void Printer::visit(While &while_block)
{
  out_ << "while (";
  visit(while_block.cond, true);
  out_ << ") ";
  visit(while_block.block);
}

void Printer::visit(Range &range)
{
  if (!range.start.is_literal() || with_types_) {
    out_ << "(";
    visit(range.start, false);
    out_ << ")";
  } else {
    visit(range.start, false);
  }
  out_ << "..";
  if (!range.end.is_literal()) {
    out_ << "(";
    visit(range.end, false);
    out_ << ")";
  } else {
    visit(range.end, false);
  }
}

void Printer::visit(For &for_loop)
{
  std::string indent(depth_, ' ');
  out_ << "for (";
  visit(for_loop.decl);
  out_ << " : ";
  visit(for_loop.iterable);
  out_ << ") ";
  print_type(for_loop.ctx_type);
  visit(for_loop.block);
}

void Printer::visit(Config &config)
{
  std::string indent(depth_, ' ');

  out_ << "config = {" << std::endl;
  ++depth_;
  foreach(*this, config.stmts, true);
  --depth_;
  out_ << "}" << std::endl;
}

void Printer::visit(Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      if (jump.return_value) {
        out_ << "return ";
        visit(*jump.return_value, true);
      } else {
        out_ << "return";
      }
      break;
    case JumpType::BREAK:
      out_ << "break";
      break;
    case JumpType::CONTINUE:
      out_ << "continue";
      break;
    default:
      break;
  }
}

void Printer::visit(AttachPoint &ap)
{
  // If the original string escapes, just keep it.
  auto raw = ap.raw_input;
  if (raw == escape(raw)) {
    out_ << raw;
    return;
  }
  // Otherwise, favor the newly constructed one.
  auto rebuilt = ap.name();
  std::string escaped = escape(rebuilt);
  if (rebuilt == escaped) {
    out_ << rebuilt;
    return;
  }
  out_ << "\"" << escaped << "\"";
}

void Printer::visit(Probe &probe)
{
  bool first = true;
  for (const auto &ap : probe.attach_points) {
    if (first) {
      first = false;
    } else {
      out_ << "," << std::endl;
    }
    visit(ap);
  }
  out_ << " ";
  visit(probe.block);
  out_ << std::endl;
}

void Printer::visit(SubprogArg &arg)
{
  out_ << arg.var->ident << " : ";
  visit(arg.typeof);
}

void Printer::visit(Subprog &subprog)
{
  out_ << "fn " << subprog.name << "(";
  foreach(*this, subprog.args, false, ", ");
  out_ << ") : ";
  visit(subprog.return_type);
  out_ << " ";
  visit(subprog.block);
  out_ << std::endl;
}

void Printer::visit(Import &imp)
{
  out_ << "import \"" << imp.name << "\";" << std::endl;
}

void Printer::visit(BlockExpr &block)
{
  if (block.stmts.empty()) {
    if (block.expr.is<None>()) {
      out_ << "{}";
    } else {
      out_ << "{ ";
      visit(block.expr, false);
      out_ << " }";
    }
  } else {
    out_ << "{" << std::endl;
    depth_++;
    visit(block.stmts);
    if (!block.expr.is<None>()) {
      print_indent();
      visit(block.expr, false);
      out_ << std::endl;
    }
    depth_--;
    print_indent();
    out_ << "}";
  }
}

void Printer::visit(Comptime &comptime)
{
  out_ << "comptime ";
  visit(comptime.expr, false);
}

void Printer::visit(Program &program)
{
  bool first = true;
  auto check_first = [&] {
    if (!first) {
      out_ << std::endl;
    } else {
      first = false;
    }
  };

  if (program.header && program.header->size() > 0) {
    check_first();
    std::cerr << *program.header;
  }

  if (!program.c_statements.empty()) {
    check_first();
    foreach(*this, program.c_statements, true);
  }

  if (program.config != nullptr && !program.config->stmts.empty()) {
    check_first();
    print_meta(program.config->loc, true, 0);
    visit(program.config);
  }

  if (!program.imports.empty()) {
    check_first();
    foreach(*this, program.imports, true);
  }

  if (!program.map_decls.empty()) {
    check_first();
    foreach(*this, program.map_decls, true);
  }

  if (!program.macros.empty()) {
    check_first();
    foreach(*this, program.macros, true);
  }

  if (!program.functions.empty()) {
    check_first();
    foreach(*this, program.functions, true);
  }

  if (!program.probes.empty()) {
    check_first();
    foreach(*this, program.probes, true);
  }
}

static bool is_block(Expression &expr, bool block_ok)
{
  if (auto *if_expr = expr.as<IfExpr>()) {
    return is_block(if_expr->left, true) &&
           (if_expr->right.is<None>() || is_block(if_expr->right, true));
  } else if (block_ok && expr.is<BlockExpr>()) {
    return true;
  } else {
    return false;
  }
}

void Printer::visit(Macro &macro)
{
  out_ << "macro " << macro.name << "(";
  foreach(*this, macro.vargs, true, ", ");
  out_ << ") ";
  visit(macro.block);
  out_ << std::endl;
}

void Printer::visit(Statement &stmt)
{
  print_meta(stmt.node().loc, true, 0);
  print_indent();
  visit(stmt.value);
  // Emit a semi-colon if it is not a block statement.
  if (!stmt.is<For>() && !stmt.is<While>() && !stmt.is<Unroll>()) {
    auto *expr = stmt.as<ExprStatement>();
    if (expr == nullptr || !is_block(expr->expr, false)) {
      out_ << ";";
    }
  }
  out_ << std::endl;
}

void Printer::visit(ExprStatement &stmt)
{
  visit(stmt.expr, true);
}

void Printer::visit(Expression &expr, bool top_level)
{
  bool needs_parens = !top_level &&
                      (expr.is<Binop>() || (expr.is<Unop>() && with_types_) ||
                       expr.is<Cast>());
  if (needs_parens) {
    out_ << "(";
  }
  visit(expr.value);
  if (needs_parens) {
    out_ << ")";
  }
  print_type(expr.type());
}

void Printer::visit(const SizedType &type)
{
  out_ << typestr(type, false);
}

void Printer::print_type(const SizedType &ty)
{
  if (!with_types_ || ty.IsNoneTy())
    return;
  out_ << " /* " << typestr(ty, true);
  if (ty.IsCtxAccess())
    out_ << ", ctx: 1";
  if (ty.GetAS() != AddrSpace::none)
    out_ << ", AS(" << ty.GetAS() << ")";
  out_ << " */";
}

void Printer::print_meta(const Location &loc, bool top_level, size_t min_vspace)
{
  if (top_level) {
    size_t vspace = loc->vspace();
    vspace = std::min<size_t>(vspace, min_vspace);
    for (size_t i = 0; i < loc->vspace(); i++) {
      out_ << std::endl;
    }
  }
  const auto &comments = loc->comments();
  auto parts = util::split_string(comments, '\n');
  if (top_level) {
    for (const auto &part : parts) {
      print_indent();
      out_ << "// " << part << std::endl;
    }
  } else if (!parts.empty()) {
    out_ << "/* ";
    bool first = true;
    for (const auto &part : parts) {
      if (first) {
        first = false;
      } else {
        out_ << " ";
      }
      out_ << part;
    }
    out_ << "*/ ";
  }
}

void Printer::emit(const std::string &s)
{
  out_ << s;
}

void Printer::print_indent()
{
  for (int i = 0; i < depth_ * 2; i++) {
    out_ << ' ';
  }
}

} // namespace bpftrace::ast
