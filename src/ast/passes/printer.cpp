#include <cctype>
#include <iomanip>
#include <sstream>

#include "ast/ast.h"
#include "ast/passes/printer.h"

namespace bpftrace::ast {

template <typename T>
static Node &getnode(const T &t)
{
  if constexpr (std::is_same_v<T, Expression> || std::is_same_v<T, Statement>) {
    return t.node();
  } else {
    return *t;
  }
}

template <typename T, typename Fn>
static void foreach(std::ostream &out,
                    std::vector<T> &items,
                    const std::string &sep,
                    Fn fn)
{
  bool first = true;
  for (auto &item : items) {
    if (first) {
      first = false;
    } else {
      out << sep;
    }
    first = false;
    fn(item);
  }
}

Printer::Printer(const ASTContext &ast, std::ostream &out, Mode mode)
    : out_(out),
      mode_(mode),
      meta_(mode == Mode::Normal ? ast.build_meta_map() : MetaMap())
{
}

void Printer::visit(CStatement &cstmt)
{
  out_ << cstmt.data;
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
  foreach(out_, call.vargs, ", ", [&](auto &v) { visit(v); });
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
  print_meta(typeof);
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
       << decl.max_entries << ");";
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
  visit(binop.left);
  out_ << " " << opstr(binop) << " ";
  visit(binop.right);
}

void Printer::visit(Unop &unop)
{
  switch (unop.op) {
    case Operator::LNOT:
      out_ << "!";
      visit(unop.expr);
      break;
    case Operator::BNOT:
      out_ << "~";
      visit(unop.expr);
      break;
    case Operator::MINUS:
      out_ << "-";
      visit(unop.expr);
      break;
    case Operator::MUL:
      out_ << "*";
      visit(unop.expr);
      break;
    case Operator::PRE_INCREMENT:
      out_ << "++";
      visit(unop.expr);
      break;
    case Operator::POST_INCREMENT:
      visit(unop.expr);
      out_ << "++";
      break;
    case Operator::PRE_DECREMENT:
      out_ << "--";
      visit(unop.expr);
      break;
    case Operator::POST_DECREMENT:
      visit(unop.expr);
      out_ << "--";
      break;
    case Operator::ASSIGN:
    case Operator::EQ:
    case Operator::NE:
    case Operator::LE:
    case Operator::GE:
    case Operator::LEFT:
    case Operator::RIGHT:
    case Operator::LT:
    case Operator::GT:
    case Operator::LAND:
    case Operator::LOR:
    case Operator::PLUS:
    case Operator::DIV:
    case Operator::MOD:
    case Operator::BAND:
    case Operator::BOR:
    case Operator::BXOR:
      break;
  }
}

static bool needs_multiline(IfExpr &if_expr)
{
  auto *left_block = if_expr.left.as<BlockExpr>();
  if (left_block && !left_block->stmts.empty()) {
    return true;
  }
  auto *right_block = if_expr.right.as<BlockExpr>();
  if (right_block && !right_block->stmts.empty()) {
    return true;
  }
  auto *right_if = if_expr.right.as<IfExpr>();
  return right_if && needs_multiline(*right_if);
}

void Printer::visit(IfExpr &if_expr)
{
  if (needs_multiline(if_expr)) {
    visit_multiline(if_expr);
    return;
  }
  out_ << "if ";
  visit(if_expr.cond);
  out_ << " ";
  if (auto *left_block = if_expr.left.as<BlockExpr>()) {
    visit(*left_block);
  } else {
    out_ << "{ ";
    visit(if_expr.left);
    out_ << " }";
  }
  if (if_expr.right.is<None>()) {
    return;
  }
  out_ << " else ";
  if (auto *right_block = if_expr.right.as<BlockExpr>()) {
    print_meta(*right_block);
    visit(*right_block);
  } else {
    out_ << "{ ";
    visit(if_expr.right);
    out_ << " }";
  }
}

void Printer::visit_multiline(IfExpr &if_expr)
{
  print_meta(if_expr, 0);
  out_ << "if ";
  visit(if_expr.cond);
  out_ << " ";
  if (auto *left_block = if_expr.left.as<BlockExpr>()) {
    visit_multiline(*left_block);
  } else {
    out_ << "{";
    depth_++;
    print_indent();
    visit_bare(if_expr.left);
    depth_--;
    print_indent();
    out_ << "}";
  }
  if (auto *none = if_expr.right.as<None>()) {
    print_meta(*none);
    return;
  }
  out_ << " else ";
  if (auto *right_block = if_expr.right.as<BlockExpr>()) {
    visit_multiline(*right_block);
  } else if (auto *right_if = if_expr.right.as<IfExpr>()) {
    // This doesn't need to be wrapped in anything, since we can handle
    // parsing the `else if` directly without any brackets.
    visit_multiline(*right_if);
  } else {
    out_ << "{";
    depth_++;
    print_indent();
    visit_bare(if_expr.right);
    out_ << std::endl; // This has no node.
    depth_--;
    print_indent();
    out_ << "}";
  }
}

void Printer::visit(FieldAccess &acc)
{
  visit(acc.expr);
  out_ << "." << acc.field;
}

void Printer::visit(ArrayAccess &arr)
{
  visit(arr.expr);
  out_ << "[";
  visit(arr.indexpr);
  out_ << "]";
}

void Printer::visit(TupleAccess &acc)
{
  visit(acc.expr);
  out_ << "." << acc.index;
}

void Printer::visit(MapAccess &acc)
{
  visit(acc.map);
  out_ << "[";
  visit(acc.key);
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
    visit_bare(cast.expr);
    out_ << ")";
  } else {
    // Binops and others will be automatically parenthesized.
    visit(cast.expr);
  }
}

void Printer::visit(Tuple &tuple)
{
  out_ << "(";
  visit_bare(tuple);
  out_ << ")";
}

void Printer::visit_bare(Tuple &tuple)
{
  for (size_t i = 0; i < tuple.elems.size(); i++) {
    visit_bare(tuple.elems.at(i));
    if (i == 0 || i < tuple.elems.size() - 1) {
      out_ << ",";
    }
  }
}

void Printer::visit(AssignScalarMapStatement &assignment)
{
  visit(assignment.map);
  // Is this a compound operator?
  auto *binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<Map>() &&
      *binop->left.as<Map>() == *assignment.map) {
    out_ << " " << opstr(*binop) << "= ";
    visit_bare(binop->right);
  } else {
    out_ << " = ";
    visit_bare(assignment.expr);
  }
}

void Printer::visit(AssignMapStatement &assignment)
{
  visit(assignment.map);
  out_ << "[";
  if (auto *tuple = assignment.key.as<Tuple>()) {
    visit_bare(*tuple);
  } else {
    visit_bare(assignment.key);
  }
  out_ << "]";
  // Is this a compound operator?
  auto *binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<MapAccess>() &&
      *binop->left.as<MapAccess>()->map == *assignment.map &&
      binop->left.as<MapAccess>()->key == assignment.key) {
    out_ << " " << opstr(*binop) << "= ";
    visit_bare(binop->right);
  } else {
    out_ << " = ";
    visit_bare(assignment.expr);
  }
}

void Printer::visit(AssignVarStatement &assignment)
{
  visit(assignment.var_decl);
  // Is this a compound operator?
  auto *binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<Variable>() &&
      *binop->left.as<Variable>() == *assignment.var()) {
    out_ << " " << opstr(*binop) << "= ";
    visit_bare(binop->right);
  } else {
    out_ << " = ";
    visit_bare(assignment.expr);
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
          auto escaped = escape(v);
          if (escaped == v) {
            out_ << v;
          } else {
            out_ << "\"" << escaped << "\"";
          }
        }
      },
      assignment.value);
  out_ << ";";
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
  visit_bare(unroll.expr);
  out_ << ") ";
  visit(unroll.block);
}

void Printer::visit(While &while_block)
{
  out_ << "while (";
  visit_bare(while_block.cond);
  out_ << ") ";
  visit(while_block.block);
}

void Printer::visit(Range &range)
{
  if (!range.start.is_literal() || mode_ == Mode::Debug) {
    out_ << "(";
    visit(range.start);
    out_ << ")";
  } else {
    visit_bare(range.start);
  }
  out_ << "..";
  if (!range.end.is_literal()) {
    out_ << "(";
    visit(range.end);
    out_ << ")";
  } else {
    visit_bare(range.end);
  }
}

void Printer::visit(For &for_loop)
{
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

  out_ << "config = {";
  ++depth_;
  foreach(out_, config.stmts, "", [&](auto *v) {
    print_meta(*v, 1, 1);
    visit(*v);
  });
  out_ << std::endl;
  --depth_;
  out_ << "}";
}

void Printer::visit(Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      if (jump.return_value) {
        out_ << "return ";
        visit_bare(*jump.return_value);
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
  // The attachpoints can unfortunately contain all kinds of weirdness, and have
  // a specialized lexer that is separate from the normal parser process. This
  // lexer is applied *after* expanding the provider, so we at least normalize
  // that. However, the best thing to do here is just emit the original raw
  // string, which should contain quotes and everything needed.
  out_ << ap.raw_input;
}

void Printer::visit(Probe &probe)
{
  // Emit all attachpoints with their respective comments. These are both
  // top-level statements and require a separator.
  foreach(out_, probe.attach_points, ",", [&](auto *v) {
    print_meta(*v, 1, 1);
    visit(*v);
  });

  // Match the parsed predicate pattern, and format appropriately.
  auto *if_expr = probe.block->expr.as<IfExpr>();
  if (if_expr && probe.block->stmts.empty() && if_expr->left.is<BlockExpr>() &&
      if_expr->right.is<None>()) {
    print_meta(if_expr->cond.node(), 1, 1);
    out_ << "/";
    visit_bare(if_expr->cond);
    out_ << "/ ";
    auto *block_expr = if_expr->left.as<BlockExpr>();
    visit_multiline(*block_expr);
  } else {
    out_ << " ";
    visit_multiline(*probe.block);
  }
}

void Printer::visit(SubprogArg &arg)
{
  out_ << arg.var->ident << " : ";
  visit(arg.typeof);
}

void Printer::visit(Subprog &subprog)
{
  out_ << "fn " << subprog.name << "(";
  foreach(out_, subprog.args, ", ", [&](auto *v) {
    print_meta(*v);
    visit(*v);
  });
  out_ << ") : ";
  visit(subprog.return_type);
  out_ << " ";
  visit_multiline(*subprog.block);
}

void Printer::visit(Import &imp)
{
  out_ << "import \"" << imp.name << "\";";
}

void Printer::visit(BlockExpr &block)
{
  // We collapse a block only if it has no statements and the
  // expression is not itself an If or a block expression, which
  // need to be split out into their own lines for clarity.
  if (block.stmts.empty() && block.expr.is<IfExpr>()) {
    auto &if_expr = *block.expr.as<IfExpr>();
    print_meta(if_expr);
    visit(if_expr);
  } else if (block.stmts.empty() && block.expr.is<BlockExpr>()) {
    auto &block_expr = *block.expr.as<BlockExpr>();
    print_meta(block_expr);
    visit(block_expr);
  } else if (block.stmts.empty()) {
    if (auto *none = block.expr.as<None>()) {
      print_meta(*none);
      out_ << "{}";
    } else {
      out_ << "{ ";
      visit_bare(block.expr);
      out_ << " }";
    }
  } else {
    visit_multiline(block);
  }
}

void Printer::visit_multiline(BlockExpr &block)
{
  print_meta(block);
  auto *none = block.expr.as<None>();
  out_ << "{";
  depth_++;
  foreach(out_, block.stmts, "", [&](auto &v) {
    print_meta(v.node(), 1);
    visit(v);
  });
  if (!none) {
    print_indent();
    visit(block.expr); // Will always print inline metadata.
    out_ << std::endl; // Will be associated with the next node.
  } else {
    print_meta(*none, 1);
  }
  depth_--;
  print_indent();
  out_ << "}";
}

void Printer::visit(Comptime &comptime)
{
  out_ << "comptime ";
  visit(comptime.expr);
}

void Printer::visit(Program &program)
{
  if (program.header && program.header->size() > 0) {
    out_ << *program.header << std::endl;
  }

  if (program.config != nullptr && !program.config->stmts.empty()) {
    print_meta(*program.config, 0);
    visit(program.config);
  }

  foreach(out_, program.c_statements, "\n", [&](auto *v) {
    print_meta(*v, 1);
    visit(*v);
  });
  foreach(out_, program.imports, "\n", [&](auto *v) {
    print_meta(*v, 1);
    visit(*v);
  });
  foreach(out_, program.map_decls, "\n", [&](auto *v) {
    print_meta(*v, 1);
    visit(*v);
  });
  foreach(out_, program.macros, "\n", [&](auto *v) {
    print_meta(*v, 1);
    visit(*v);
  });
  foreach(out_, program.functions, "\n", [&](auto *v) {
    print_meta(*v, 1);
    visit(*v);
  });
  foreach(out_, program.probes, "\n", [&](auto *v) {
    print_meta(*v, 1);
    visit(*v);
  });

  // Files always end with a newline.
  out_ << std::endl;
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
  foreach(out_, macro.vargs, ", ", [&](auto &v) { visit_bare(v); });
  out_ << ") ";
  visit(macro.block);
}

void Printer::visit(Statement &stmt)
{
  print_indent();
  visit(stmt.value);
  // Emit a semi-colon if it is not a block statement.
  if (!stmt.is<For>() && !stmt.is<While>() && !stmt.is<Unroll>()) {
    auto *expr = stmt.as<ExprStatement>();
    if (expr == nullptr || !is_block(expr->expr, false)) {
      out_ << ";";
    }
  }
}

void Printer::visit(ExprStatement &stmt)
{
  visit_bare(stmt.expr);
}

void Printer::visit(Expression &expr)
{
  bool needs_parens = expr.is<Binop>() ||
                      (expr.is<Unop>() && mode_ == Mode::Debug) ||
                      (expr.is<Cast>() && mode_ == Mode::Debug);
  if (needs_parens) {
    out_ << "(";
  }
  visit_bare(expr);
  if (needs_parens) {
    out_ << ")";
  }
  print_type(expr.type());
}

void Printer::visit_bare(Expression &expr)
{
  print_meta(expr.node());
  visit(expr.value);
}

void Printer::visit(const SizedType &type)
{
  out_ << typestr(type, false);
}

void Printer::print_type(const SizedType &ty)
{
  if (mode_ != Mode::Debug || ty.IsNoneTy())
    return;
  out_ << " /* " << typestr(ty, true);
  if (ty.IsCtxAccess())
    out_ << ", ctx: 1";
  if (ty.GetAS() != AddrSpace::none)
    out_ << ", AS(" << ty.GetAS() << ")";
  out_ << " */";
}

void Printer::print_meta(const Node &node,
                         std::optional<size_t> min_vspace,
                         std::optional<size_t> max_vspace)
{
  bool inline_style = !min_vspace.has_value();
  auto metadata = meta_.pop(node);
  if (!inline_style) {
    size_t total_vspace = 0;
    if (min_vspace) {
      for (size_t i = 0; i < *min_vspace; i++) {
        out_ << std::endl;
      }
    }
    for (const auto &part : metadata) {
      if (std::holds_alternative<size_t>(part)) {
        for (size_t i = 0; i < std::get<size_t>(part); i++) {
          if (min_vspace && total_vspace < *min_vspace) {
            // Already done above.
          } else if (max_vspace && total_vspace >= *max_vspace) {
            // Omitted.
          } else {
            out_ << std::endl;
          }
          total_vspace++;
        }
      } else {
        print_indent();
        auto &s = std::get<std::string>(part);
        if (s.empty()) {
          out_ << "//" << std::endl;
        } else {
          out_ << "// " << s << std::endl;
        }
      }
    }
  } else {
    // In the style is inline, then we drop any vertical space.
    // This is basically condensing comments that are inline for
    // an expression into an inline comment. If they should be
    // multiple lines, then they can associated with a top-level
    // node, like the statement itself.
    bool first = true;
    for (const auto &part : metadata) {
      if (std::holds_alternative<std::string>(part)) {
        if (first) {
          out_ << "/* ";
          first = false;
        } else {
          out_ << " ";
        }
        out_ << std::get<std::string>(part);
      }
      if (!first) {
        out_ << "*/ ";
      }
    }
  }
}

void Printer::print_indent()
{
  for (int i = 0; i < depth_ * 2; i++) {
    out_ << ' ';
  }
}

} // namespace bpftrace::ast
