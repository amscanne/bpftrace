#include <cctype>
#include <sstream>
#include <variant>

#include "ast/ast.h"
#include "ast/passes/printer.h"

namespace bpftrace::ast {

namespace {
struct Text {
  Text(std::string data) : data(std::move(data)) {};
  std::string data;
};
struct Comment {
  Comment(std::string data) : data(std::move(data)) {};
  std::string data;
};
struct Line {
  Line() = default;
  size_t columns() const
  {
    size_t total = 0;
    for (const auto& seg : segments) {
      if (std::holds_alternative<Text>(seg)) {
        total += std::get<Text>(seg).data.size();
      } else if (std::holds_alternative<Comment>(seg)) {
        total += std::get<Comment>(seg).data.size();
      }
    }
    return total;
  }
  std::vector<std::variant<Text, Comment>> segments;
};
} // namespace

struct BufferState {
  std::vector<Line> lines;
  size_t current_depth = 0;
};

Buffer::Buffer() : state(std::make_unique<BufferState>())
{
  state->lines.emplace_back(Line());
};

Buffer& Buffer::append(Buffer&& other)
{
  // Remember our current column.
  size_t col = state->lines.back().columns();
  // We extend from our current final line.
  for (auto& line : other.state->lines) {
    // Move over to the column from before.
    if (state->lines.back().segments.empty()) {
      state->lines.back().segments.emplace_back(Text(std::string(col, ' ')));
    }
    // Extend our last line, e.g. lines.back().
    state->lines.back().segments.insert(
        state->lines.back().segments.end(),
        std::make_move_iterator(line.segments.begin()),
        std::make_move_iterator(line.segments.end()));
    line_break();
  }
  return *this;
}

Buffer& Buffer::text(std::string str)
{
  state->lines.back().segments.emplace_back(Text(std::move(str)));
  return *this;
}

Buffer& Buffer::comment(std::string str)
{
  state->lines.back().segments.emplace_back(Comment(std::move(str)));
  return *this;
}

Buffer& Buffer::line_break()
{
  state->lines.emplace_back(Line());
  return *this;
}

template <typename T, typename Fn>
static void foreach(std::ostream& out,
                    std::vector<T>& items,
                    const std::string& sep,
                    Fn fn)
{
  bool first = true;
  for (auto& item : items) {
    if (first) {
      first = false;
    } else {
      out << sep;
    }
    first = false;
    fn(item);
  }
}

static bool is_primitive(const Expression& expr)
{
  if (expr.is<Integer>() || expr.is<NegativeInteger>() || expr.is<String>() ||
      expr.is<Boolean>() || expr.is<PositionalParameter>() ||
      expr.is<PositionalParameterCount>() || expr.is<None>() ||
      expr.is<Identifier>() || expr.is<Builtin>() || expr.is<Sizeof>() ||
      expr.is<Offsetof>() || expr.is<Typeinfo>() || expr.is<Variable>() ||
      expr.is<ArrayAccess>() || expr.is<TupleAccess>() ||
      expr.is<MapAccess>() || expr.is<Call>() || expr.is<Map>()) {
    return true;
  }
  if (auto* comptime = expr.as<Comptime>()) {
    return is_primitive(comptime->expr);
  }
  return false;
}

Buffer Formatter<CStatement>::format(const CStatement& cstmt)
{
  return Buffer().append(cstmt.data).line_break();
}

Buffer Formatter<Integer>::format(const Integer& integer)
{
  if (integer.original) {
    // This typically means that it has special characters such as separately,
    // suffixes, etc. We preserve these as an esthetic choice.
    out_ << *integer.original;
  } else {
    out_ << integer.value;
  }
}

Buffer Formatter<NegativeInteger>::format(const NegativeInteger& integer)
{
  out_ << integer.value;
}

Buffer Formatter<Boolean>::format(const Boolean& boolean)
{
  if (boolean.value) {
    out_ << "true";
  } else {
    out_ << "false";
  }
}

Buffer Formatter<PositionalParameter>::format(const PositionalParameter& param)
{
  out_ << "$" << param.n;
}

Buffer Formatter<[[maybe_unused]] PositionalParameterCount>::format(
    const [[maybe_unused]] PositionalParameterCount& param)
{
  out_ << "$#";
}

static std::string escape(const std::string& s)
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

Buffer Formatter<String>::format(const String& string)
{
  out_ << "\"" << escape(string.value) << "\"";
}

Buffer Formatter<[[maybe_unused]] None>::format(const
                                                [[maybe_unused]] None& none)
{
  // Does not have a syntactic representation.
}

Buffer Formatter<Builtin>::format(const Builtin& builtin)
{
  out_ << builtin.ident;
}

Buffer Formatter<Identifier>::format(const Identifier& identifier)
{
  out_ << identifier.ident;
}

Buffer Formatter<Call>::format(const Call& call)
{
  out_ << call.func;
  out_ << "(";
  foreach(out_, call.vargs, ", ", [&](auto& v) { visit_bare(v); });
  out_ << ")";
}

Buffer Formatter<Sizeof>::format(const Sizeof& szof)
{
  out_ << "sizeof(";
  visit(szof.record);
  out_ << ")";
}

Buffer Formatter<Offsetof>::format(const Offsetof& offof)
{
  out_ << "offsetof(";
  visit(offof.record);
  out_ << ", ";
  foreach(out_, offof.field, ".", [&](auto& v) { out_ << v; });
}

Buffer Formatter<Typeof>::format(const Typeof& typeof)
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

Buffer Formatter<Typeinfo>::format(const Typeinfo& typeinfo)
{
  out_ << "typeinfo(";
  if (std::holds_alternative<Expression>(typeinfo.typeof->record)) {
    // Omit the `typeof` for `typeinfo`.
    visit(typeinfo.typeof->record);
  } else {
    // Use the default representation.
    visit(typeinfo.typeof);
  }
  out_ << ")";
}

Buffer Formatter<MapDeclStatement>::format(const MapDeclStatement& decl)
{
  out_ << "let " << decl.ident << " = " << decl.bpf_type << "("
       << decl.max_entries << ");" << std::endl;
}

Buffer Formatter<Map>::format(const Map& map)
{
  out_ << map.ident;
}

Buffer Formatter<MapAddr>::format(const MapAddr& map_addr)
{
  out_ << "&" << map_addr.map->ident;
}

Buffer Formatter<Variable>::format(const Variable& var)
{
  out_ << var.ident;
}

Buffer Formatter<VariableAddr>::format(const VariableAddr& var_addr)
{
  out_ << "&" << var_addr.var->ident;
}

static bool is_comparison(const Binop& binop)
{
  switch (binop.op) {
    case Operator::EQ:
    case Operator::NE:
    case Operator::LE:
    case Operator::GE:
    case Operator::LT:
    case Operator::GT:
      return true;
    default:
      return false;
  }
  return false;
}

Buffer Formatter<Binop>::format(const Binop& binop)
{
  // Special case: allow chaining of comparisons. We don't strictly
  // require the use of nested brackets as long as the comparison
  // is ambiguious, but we will add brackets if either side involves
  // other comparison operators.
  bool is_logical = binop.op == Operator::LAND || binop.op == Operator::LOR;
  auto left_ok = is_primitive(binop.left) ||
                 (binop.left.is<Binop>() &&
                  is_comparison(*binop.left.as<Binop>())) ||
                 (binop.left.is<Binop>() &&
                  binop.left.as<Binop>()->op == binop.op);
  auto right_ok = is_primitive(binop.right) ||
                  (binop.right.is<Binop>() &&
                   is_comparison(*binop.right.as<Binop>())) ||
                  (binop.right.is<Binop>() &&
                   binop.right.as<Binop>()->op == binop.op);
  if (is_logical && left_ok && right_ok) {
    visit_bare(binop.left);
    out_ << " " << opstr(binop) << " ";
    visit_bare(binop.right);
    return;
  } else {
    visit(binop.left);
    out_ << " " << opstr(binop) << " ";
    visit(binop.right);
  }
}

Buffer Formatter<Unop>::format(const Unop& unop)
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

Buffer Formatter<IfExpr>::format(const IfExpr& if_expr)
{
  bool needs_multiline = !is_primitive(if_expr.left) ||
                         !is_primitive(if_expr.right);
  if (needs_multiline) {
    visit_multiline(if_expr);
    return;
  }
  // This just emits a single line if expression, which may be
  // nested and shouldn't have any immediate newline, etc.
  out_ << "if ";
  if (if_expr.cond.is<Comptime>()) {
    // Special case: comptime is bare for if expressions.
    visit_bare(if_expr.cond);
  } else {
    visit(if_expr.cond);
  }
  out_ << " { ";
  visit_bare(if_expr.left);
  out_ << " }";
  if (if_expr.right.is<None>()) {
    return;
  }
  out_ << " else { ";
  visit_bare(if_expr.right);
  out_ << " }";
}

void Printer::visit_multiline(IfExpr& if_expr)
{
  out_ << "if ";
  if (if_expr.cond.is<Comptime>()) {
    // See above; special case.
    visit_bare(if_expr.cond);
  } else {
    visit(if_expr.cond);
  }
  out_ << " ";
  if (auto* left_block = if_expr.left.as<BlockExpr>()) {
    print_meta(*left_block); // Eat as inline.
    visit_multiline(*left_block);
  } else {
    out_ << "{" << std::endl;
    depth_++;
    print_meta(if_expr.left.node(), 0);
    print_indent();
    visit_bare(if_expr.left); // Metadata pulled up.
    depth_--;
    print_indent();
    out_ << "}";
  }
  if (if_expr.right.is<None>()) {
    return;
  }
  out_ << " else ";
  if (auto* right_block = if_expr.right.as<BlockExpr>()) {
    print_meta(*right_block); // Metadata pulled inline.
    visit_multiline(*right_block);
  } else if (auto* right_if = if_expr.right.as<IfExpr>()) {
    // This doesn't need to be wrapped in anything, since we can handle
    // parsing the `else if` directly without any brackets.
    print_meta(*right_if); // See above.
    visit_multiline(*right_if);
  } else {
    out_ << "{" << std::endl;
    depth_++;
    print_meta(if_expr.right.node(), 0);
    print_indent();
    visit_bare(if_expr.right);
    out_ << std::endl;
    depth_--;
    print_indent();
    out_ << "}";
  }
}

Buffer Formatter<FieldAccess>::format(const FieldAccess& acc)
{
  // Special case: allow chaining of field accesses.
  if (is_primitive(acc.expr) || acc.expr.is<FieldAccess>()) {
    visit_bare(acc.expr);
  } else {
    visit(acc.expr);
  }
  out_ << "." << acc.field;
}

Buffer Formatter<ArrayAccess>::format(const ArrayAccess& arr)
{
  visit(arr.expr);
  out_ << "[";
  visit(arr.indexpr);
  out_ << "]";
}

Buffer Formatter<TupleAccess>::format(const TupleAccess& acc)
{
  visit(acc.expr);
  out_ << "." << acc.index;
}

Buffer Formatter<MapAccess>::format(const MapAccess& acc)
{
  visit(acc.map);
  out_ << "[";
  visit(acc.key);
  out_ << "]";
}

Buffer Formatter<Cast>::format(const Cast& cast)
{
  out_ << "(";
  visit(cast.typeof);
  out_ << ")";
  visit(cast.expr);
}

Buffer Formatter<Tuple>::format(const Tuple& tuple)
{
  out_ << "(";
  visit_bare(tuple);
  out_ << ")";
}

void Printer::visit_bare(Tuple& tuple)
{
  for (size_t i = 0; i < tuple.elems.size(); i++) {
    visit_bare(tuple.elems.at(i));
    if (i == 0 || i < tuple.elems.size() - 1) {
      out_ << ",";
    }
  }
}

Buffer Formatter<AssignScalarMapStatement>::format(
    const AssignScalarMapStatement& assignment)
{
  visit(assignment.map);
  // Is this a compound operator?
  auto* binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<Map>() &&
      *binop->left.as<Map>() == *assignment.map) {
    out_ << " " << opstr(*binop) << "= ";
    visit_bare(binop->right);
  } else {
    out_ << " = ";
    visit_bare(assignment.expr);
  }
}

Buffer Formatter<AssignMapStatement>::format(
    const AssignMapStatement& assignment)
{
  visit(assignment.map);
  out_ << "[";
  if (auto* tuple = assignment.key.as<Tuple>()) {
    visit_bare(*tuple);
  } else {
    visit_bare(assignment.key);
  }
  out_ << "]";
  // Is this a compound operator?
  auto* binop = assignment.expr.as<Binop>();
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

Buffer Formatter<AssignVarStatement>::format(
    const AssignVarStatement& assignment)
{
  visit(assignment.var_decl);
  // Is this a compound operator?
  auto* binop = assignment.expr.as<Binop>();
  if (binop && binop->left.is<Variable>() &&
      *binop->left.as<Variable>() == *assignment.var()) {
    out_ << " " << opstr(*binop) << "= ";
    visit_bare(binop->right);
  } else {
    out_ << " = ";
    visit_bare(assignment.expr);
  }
}

Buffer Formatter<AssignConfigVarStatement>::format(
    const AssignConfigVarStatement& assignment)
{
  out_ << assignment.var << " = ";
  std::visit(
      [&](auto& v) {
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
  out_ << ";" << std::endl;
}

Buffer Formatter<VarDeclStatement>::format(const VarDeclStatement& decl)
{
  out_ << "let ";
  visit(decl.var);
  if (decl.typeof) {
    out_ << " : ";
    visit(decl.typeof);
  }
}

Buffer Formatter<Unroll>::format(const Unroll& unroll)
{
  out_ << "unroll (";
  visit_bare(unroll.expr);
  out_ << ") ";
  visit(unroll.block);
}

Buffer Formatter<While>::format(const While& while_block)
{
  out_ << "while (";
  visit_bare(while_block.cond);
  out_ << ") ";
  visit(while_block.block);
}

Buffer Formatter<Range>::format(const Range& range)
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

Buffer Formatter<For>::format(const For& for_loop)
{
  out_ << "for (";
  visit(for_loop.decl);
  out_ << " : ";
  visit(for_loop.iterable);
  out_ << ") ";
  print_type(for_loop.ctx_type);
  visit(for_loop.block);
}

Buffer Formatter<Config>::format(const Config& config)
{
  std::string indent(depth_, ' ');

  out_ << "config = {" << std::endl;
  ++depth_;
  foreach(out_, config.stmts, "", [&](auto* v) {
    print_meta(*v);
    print_indent();
    visit(*v);
  });
  print_meta(metadata_.pop_until(config.loc->current.end), 0);
  --depth_;
  out_ << "}" << std::endl;
}

Buffer Formatter<Jump>::format(const Jump& jump)
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

Buffer Formatter<AttachPoint>::format(const AttachPoint& ap)
{
  // The attachpoints can unfortunately contain all kinds of weirdness, and have
  // a specialized lexer that is separate from the normal parser process. This
  // lexer is applied *after* expanding the provider, so we at least normalize
  // that. However, the best thing to do here is just emit the original raw
  // string, which should contain quotes and everything needed.
  out_ << ap.raw_input;
}

Buffer Formatter<Probe>::format(const Probe& probe)
{
  // Emit all attachpoints with their respective comments. These are both
  // top-level statements and require a separator. If the user has them
  // specified inline, they will be preserved in that way.
  foreach(out_, probe.attach_points, ", ", [&](auto* v) {
    print_meta(*v, 0); // Users *may* inject breaks to attachpoints.
    visit(*v);
  });

  // Match the parsed predicate pattern, and format appropriately.
  auto* if_expr = probe.block->expr.as<IfExpr>();
  if (if_expr && probe.block->stmts.empty() && if_expr->left.is<BlockExpr>() &&
      if_expr->right.is<None>()) {
    // The predicate also *may* be given its own line, this is
    // not enforced strictly just like the attachpoints.
    print_meta(if_expr->cond.node(), 0);
    out_ << "/";
    visit_bare(if_expr->cond);
    out_ << "/ ";
    auto* block_expr = if_expr->left.as<BlockExpr>();
    print_meta(*block_expr, 0); // See above, allow breaks.
    visit_multiline(*block_expr);
  } else {
    out_ << " ";
    print_meta(*probe.block, 0); // Allow breaks for style.
    visit_multiline(*probe.block);
  }
  out_ << std::endl;
}

Buffer Formatter<SubprogArg>::format(const SubprogArg& arg)
{
  out_ << arg.var->ident << " : ";
  visit(arg.typeof);
}

Buffer Formatter<Subprog>::format(const Subprog& subprog)
{
  out_ << "fn " << subprog.name << "(";
  foreach(out_, subprog.args, ", ", [&](auto* v) {
    print_meta(*v);
    visit(*v);
  });
  out_ << ") : ";
  visit(subprog.return_type);
  out_ << " ";
  visit(*subprog.block);
  out_ << std::endl;
}

Buffer Formatter<Import>::format(const Import& imp)
{
  out_ << "import \"" << imp.name << "\";";
}

Buffer Formatter<BlockExpr>::format(const BlockExpr& block)
{
  // We collapse a block only if it has no statements and the
  // expression is not itself a block expression.
  if (block.stmts.empty() && block.expr.is<BlockExpr>()) {
    auto& block_expr = *block.expr.as<BlockExpr>();
    visit(block_expr);
    return;
  }

  // If the macro has statements or has a non-trivial expression,
  // then we require that it is emitted as a multi-line block.
  if (!block.stmts.empty() || !is_primitive(block.expr)) {
    visit_multiline(block);
    return;
  }

  // This is a single inline expression block, but we ensure
  // that it captures all of the metadata until the end of the
  // block. This may include inline comments.
  if (block.expr.is<None>()) {
    // If there are comments in the block, we convert to the
    // multi-line style for comment clarity. Otherwise, it's
    // just an empty block with no expressions at all.
    auto metadata = metadata_.pop_until(block.loc->current.end);
    if (!metadata.empty()) {
      out_ << "{" << std::endl;
      print_meta(metadata, 0);
      print_indent();
      out_ << "}";
    } else {
      out_ << "{}";
    }
  } else {
    // We convert to a multi-line block if the expression has any
    // comments. Otherwise, we leave trailing comments as inline.
    auto pre_metadata = metadata_.pop_until(block.expr.loc()->current.begin);
    if (!pre_metadata.empty()) {
      out_ << "{" << std::endl;
      depth_++;
      print_meta(pre_metadata, 0);
      print_indent();
      visit_bare(block.expr);
      out_ << std::endl;
      auto post_metadata = metadata_.pop_until(block.loc->current.end);
      print_meta(post_metadata, 0);
      depth_--;
      print_indent();
      out_ << "}";
    } else {
      out_ << "{ ";
      visit_bare(block.expr);
      auto post_metadata = metadata_.pop_until(block.loc->current.end);
      print_meta(post_metadata); // Inline style.
      out_ << " }";
    }
  }
}

void Printer::visit_multiline(BlockExpr& block)
{
  // Start the block.
  out_ << "{" << std::endl;
  depth_++;

  // Print our all statements; these will automatically have a newline.
  foreach(out_, block.stmts, "", [&](auto& v) { visit(v); });

  // Include an expression if needed.
  auto* none = block.expr.as<None>();
  if (!none) {
    print_meta(block.expr.node(), 0);
    print_indent();
    visit_bare(block.expr); // Metadata pulled up above.
    // See below re: newline.
  }

  // Print any stranded metadata within the block. Note that we
  // expect this to include a newline if there was an expression
  // above, because that won't have its newline eaten.
  auto metadata = metadata_.pop_until(block.loc->current.end);
  print_meta(metadata, none ? 0 : 1);

  depth_--;
  print_indent();
  out_ << "}";
}

Buffer Formatter<Comptime>::format(const Comptime& comptime)
{
  out_ << "comptime ";
  visit(comptime.expr);
}

static std::string rtrim(const std::string& s)
{
  size_t end = s.size();
  while (end > 0 && std::isspace(s[end - 1])) {
    end--;
  }
  return s.substr(0, end);
}

Buffer Formatter<Program>::format(const Program& program)
{
  out_.str(""); // Reset our stream.

  if (program.header && program.header->size() > 0) {
    out_ << *program.header << std::endl;
  }

  // We preserve the order of all the top-level statements. By using
  // this map, we will iterate through them in order. The parser can
  // support strict ordering if it likes, but for printing we want to
  // ensure that we are respecting the original source order.
  std::map<SourceLocation, RootStatement> top_level;

  if (program.config != nullptr && !program.config->stmts.empty()) {
    top_level.emplace(program.config->loc->current, program.config);
  }
  for (auto* import : program.imports) {
    top_level.emplace(import->loc->current, import);
  }
  for (auto* cstmt : program.c_statements) {
    top_level.emplace(cstmt->loc->current, cstmt);
  }
  for (auto* map_decl : program.map_decls) {
    top_level.emplace(map_decl->loc->current, map_decl);
  }
  for (auto* macro : program.macros) {
    top_level.emplace(macro->loc->current, macro);
  }
  for (auto* function : program.functions) {
    top_level.emplace(function->loc->current, function);
  }
  for (auto* probe : program.probes) {
    top_level.emplace(probe->loc->current, probe);
  }

  for (auto& [_, entry] : top_level) {
    print_meta(entry.node(), 0);
    visit(entry);
  }

  // It's possible that there are trailing comments, not associated with any
  // macros, probes or functions. Include these at the end, where they were.
  auto metadata = metadata_.pop_until(program.loc->current.end);
  print_meta(metadata, 0);

  // Finally, there are some cases where we could emit { \n sequences, and
  // we want to simply clean those up to remove trailing whitespace.
  std::string line;
  while (std::getline(out_, line)) {
    real_out_ << rtrim(line) << std::endl;
  }
}

Buffer Formatter<Macro>::format(const Macro& macro)
{
  out_ << "macro " << macro.name << "(";
  foreach(out_, macro.vargs, ", ", [&](auto& v) { visit_bare(v); });
  out_ << ") ";
  visit(*macro.block);
  out_ << std::endl;
}

Buffer Formatter<Statement>::format(const Statement& stmt)
{
  // Special case: do nothing for no-op statements.
  if (stmt.is<ExprStatement>() && stmt.as<ExprStatement>()->expr.is<None>()) {
    return;
  }
  print_meta(stmt.node(), 0);
  print_indent();
  visit(stmt.value);
  // Emit a semi-colon if it is not a block statement. We always need
  // ifs to lack the semi-colon, even if they are parsed as an expression.
  if (!stmt.is<For>() && !stmt.is<While>() && !stmt.is<Unroll>()) {
    auto* expr_stmt = stmt.as<ExprStatement>();
    if (!expr_stmt || !expr_stmt->expr.is<IfExpr>()) {
      out_ << ";";
    }
  }
  out_ << std::endl;
}

Buffer Formatter<ExprStatement>::format(const ExprStatement& stmt)
{
  visit_bare(stmt.expr);
}

Buffer Formatter<Expression>::format(const Expression& expr)
{
  bool bare_okay = mode_ != Mode::Debug && is_primitive(expr);
  if (!bare_okay) {
    out_ << "(";
  }
  visit_bare(expr);
  if (!bare_okay) {
    out_ << ")";
  }
  print_type(expr.type());
}

void Printer::visit_bare(Expression& expr)
{
  auto pre_metadata = metadata_.pop_until(expr.loc()->current.begin);
  print_meta(pre_metadata);
  visit(expr.value);
  // It is possible that this was included already, e.g. in a block,
  // or a multiline if or one of many other places. However, if it
  // hasn't been pulled already, then we emit as a trailing comment.
  auto post_metadata = metadata_.pop_until(expr.loc()->current.end);
  print_meta(post_metadata);
}

Buffer Formatter<const SizedType>::format(const const SizedType& type)
{
  out_ << typestr(type, false);
}

void Printer::print_type(const SizedType& ty)
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

void Printer::print_meta(const Node& node, std::optional<size_t> min_vspace)
{
  const auto& pos = node.loc->current.begin;
  print_meta(metadata_.pop_until(pos), min_vspace);
}

void Printer::print_meta(const std::vector<MetadataIndex::Variant>& metadata,
                         std::optional<size_t> min_vspace)
{
  bool inline_style = !min_vspace.has_value();
  if (!inline_style) {
    size_t total_vspace = 0;
    if (min_vspace) {
      for (size_t i = 0; i < *min_vspace; i++) {
        out_ << std::endl;
      }
    }
    for (const auto& part : metadata) {
      if (std::holds_alternative<size_t>(part)) {
        for (size_t i = 0; i < std::get<size_t>(part); i++) {
          if (min_vspace && total_vspace < *min_vspace) {
            // Already done above.
          } else {
            out_ << std::endl;
          }
          total_vspace++;
        }
      } else {
        print_indent();
        const auto& s = std::get<std::string>(part);
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
    for (const auto& part : metadata) {
      if (std::holds_alternative<std::string>(part)) {
        if (first) {
          out_ << " /* ";
          first = false;
        }
        out_ << std::get<std::string>(part);
      }
    }
    if (!first) {
      out_ << " */";
    }
  }
}

void Printer::print_indent()
{
  for (int i = 0; i < depth_ * 2; i++) {
    out_ << ' ';
  }
}

void Printer::emit(std::function<void(Buffer&)> fn)
{
  Buffer buffer;
  fn(buffer);
  out_ << buffer;
}

} // namespace bpftrace::ast
