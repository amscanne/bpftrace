#include <sstream>

#include "parser/parser.h"

namespace bpftrace::parser {

namespace {

class ProgramParser : public Parser<ProgramParser> {
public:
  ProgramParser(tokenizer::Tokenizer& tok, ASTContext &ast) : Parser<ProgramParser>(tok), ast_(ast) {};

  // Parse a complete program, see docs below.
  Result<ast::Program*> parse();

private:
  ASTContext& ast_;
};

} // namespace

static std::unordered_map<std::string, SizedType> builtins = {
  { "void", CreateVoid() },
  { "min_t", CreateMin(true) },
  { "max_t", CreateMax(true) },
  { "sum_t", CreateSum(true) },
  { "count_t", CreateCount(true) },
  { "avg_t", CreateAvg(true) },
  { "stats_t", CreateStats(true) },
  { "umin_t", CreateMin(false) },
  { "umax_t", CreateMax(false) },
  { "usum_t", CreateSum(false) },
  { "ucount_t", CreateCount(false) },
  { "uavg_t", CreateAvg(false) },
  { "ustats_t", CreateStats(false) },
  { "timestamp", CreateTimestamp() },
  { "macaddr_t", CreateMacAddress() },
  { "cgroup_path_t", CreateCgroupPath() },
  { "strerror_t", CreateStrerror() },
};

static std::unordered_map<std::string, SizedType> integers = {
  { "bool", CreateBool() },     { "uint8", CreateUInt(8) },
  { "uint16", CreateUInt(16) }, { "uint32", CreateUInt(32) },
  { "uint64", CreateUInt(64) }, { "int8", CreateInt(8) },
  { "int16", CreateInt(16) },   { "int32", CreateInt(32) },
  { "int64", CreateInt(64) },
};

std::optional<SizedType> parse_type()
{
  // We handle only the identifier cases here, if this looks like pointer type
  // then we pass to parse_unop_expr to resolve.
  if (!match(Token::IDENT)) {
    auto maybeType = parse_unop();
    if (!std::holds_alternative<SizedType>(maybeType)) {
      fail() << "unexpected type, found expression";
      return std::nullopt;
    }
    return *std::get<SizedType>(&maybeType);
  }

  // We pull the identifier name but don't consume it yet. The `parse_type`
  // function will not consume any tokens if the type cannot be parsed safely.
  auto name = tokenizer_.current().contents();

  // Builtin types may not be composed into arrays or anything else. Users
  // will receive an array when parsing the next token in these cases.
  if (builtins.find(name) != builtins.end()) {
    if (matchAny(OPEN_BRACKET, MUL)) {
      fail() << "builtin types may not be used as pointers or arrays";
      return CreateVoid();
    }
    return *builtins.find(name);
  }

  // The following types are composed, and we check if they match an array
  // declaration.
  std::optional<SizedType> base;
  if (name == "string") {
    base = CreateString(0);
  } else if (name == "inet") {
    base = CreateInet(0);
  } else if (name == "buffer") {
    base = CreateBuffer(0);
  } else if (name == "struct") {
    consume(IDENT); // The `struct` token.
    if (!match(IDENT)) {
      fail() << "unexpected token following `struct`";
      return CreateVoid();
    }
    auto struct_name = tokenizer_.current().contents();
    base = ident_to_record(struct_name);
  } else if (integers.find(name) != integers.end()) {
    base = *integers.find(name);
  } else {
    return std::nullopt; // Not a type.
  }

  // Now we can consume the identifier and determine if this is referring to an
  // array type or something else. After this point, we are committed to
  // returning a type because we will have consumed the token.
  consume(IDENT);

  // Now the only legal suffix to the type is an array, e.g. '['. If it is not
  // this, then we consider the type finished.
  while (match(Token::OPEN_BRACKET)) {
    consume(Token::OPEN_BRACKET);
    if (match(Token::INTEGER)) {
      auto count = parse_int(consume(INTEGER));
      consume(Token::CLOSE_BRACKET);
      base = CreateArray(count, *base);
    } else if (match(CLOSE_BRACKET)) {
      consume(Token::CLOSE_BRACKET);
      base = CreateArray(0, *base);
    } else {
      fail() << "mangled type name";
      return CreateVoid();
    }
  }

  return *base;
}

Result<AssignConfigVarStatement*> parse_config_assign_statement()
{
  auto name = consume(IDENT);
  if (!name) {
    return name.takeError();
  }
  consume(OP, Operator::ASSIGN);
  auto value = must(parse_expr);
  return make<AssignConfigVarStatement>(name, value);
}

Result<StatementList> parse_config()
{
  consume(IDENT, "config");
  consume(OP, Operator::ASSIGN);
  consume(OPEN_BRACE);
  auto stats = make<StatementList>();
  while (!match(CLOSE_BRACE)) {
    stmts.push_back(must(parse_config_assign_statement));
  }
  consume(CLOSE_BRACE);
  return make<Config>(stmts);
}

Result<SubprogArgList> parse_subprog_args()
{
  consume(OPEN_PAREN);
  auto args = make<SubprogArgs>();
  while (!match(CLOSE_PAREN)) {
    if (args.size() > 0)
      consume(COMMA);
    auto var = must(parse_var);
    consume(COLON);
    auto typ = must(parse_type);
    args.emplace_back(make<SubprogArg>(var, typ));
  }
  consume(CLOSE_PAREN);
  return make<SubprogArg>(args);
}

Result<Subprog*> parse_subprog()
{
  consume(IDENT, "fn");
  auto name = consume(IDENT);
  auto args = must(parse_subprog_args);
  auto rtyp = must(parse_type);
  auto block = must(parse_block);
  return make<Subprog>(name, args, rtyp, block);
}

Probe& parse_probe()
{
  auto attach_points = must(parse_attach_points);
  auto predicate = must(parse_predicate);
  auto block = must(parse_block);
  return make<Probe>(attach_points, predicate, block);
}

AttachPointList& parse_attach_points()
{
  auto list = make<AttachPointList>();
  while (true) {
    list.push_back(must(parse_attach_point));
    if (!match(COMMA))
      break;
    consume(COMMA);
  }
  return list;
}

AttachPoint& parse_attach_point()
{
  return make<AttachPoint>(consume(IDENT,
                                   STRING,
                                   INT,
                                   COLON,
                                   DOT,
                                   PLUS,
                                   MUL,
                                   OPEN_BRACKET,
                                   CLOSE_BRACKET,
                                   VAR));
}

Predicate& parse_predicate()
{
  if (match(DIV)) {
    consume(DIV);
    auto expr = must(parse_expr);
    consume(DIV);
    return make<Predicate>(expr);
  }
  return make<Predicate>();
}

Statement& parse_naked_statement()
{
  if (matchAll(IDENT, "for"))
    return must(parse_for);
  else if (matchAll(IDENT, "if"))
    return must(parse_if);
  else if (matchAll(IDENT, "while"))
    return must(parse_while);
  else if (matchAll(IDENT, "break"))
    return must(parse_break);
  else if (matchAll(IDENT, "return"))
    return must(parse_return);
  else if (matchAll(IDENT, "unroll"))
    return must(parse_unroll);
  else if (matchAll(IDENT, "continue"))
    return must(parse_continue);
  else if (matchAll(IDENT, "let"))
    return must(parse_decl);

  // Assignment statements are technically expressions as well, so they
  // are resolved through the `parse_expr` path.
  else
    return must(parse_expr);
}

Statement& parse_statement()
{
  auto stmt = must(parse_naked_statement);
  while (match(SEMI_COLON))
    consume(SEMI_COLON);
  return stmt;
}

Unroll& parse_unroll()
{
  consume(UNROLL);
  consume(OPEN_PAREN);
  auto expr = must(parse_expr);
  consume(CLOSE_PAREN);
  return make<Unroll>(expr, must(parse_optional_block));
}

For& parse_for()
{
  consume(FOR);
  consume(OPEN_PAREN);
  auto var = must(parse_var);
  consume(COLON);
  auto expr = parse_expr();
  consume(CLOSE_PAREN);
  return make<For>(var, expr, must(parse_optional_block));
}

Block& parse_block()
{
  auto stmts = make<StatementList>();
  consume(OPEN_BRACE);
  while (!match(CLOSE_BRANCH)) {
    stmts.push_back(must(parse_statement));
  }
  consume(CLOSE_BRACE);
  return make<Block>(stmts);
}

Block& parse_optional_block()
{
  if (match(OPEN_BRACE)) {
    return must(parse_block);
  }
  auto stmts = make<StatementList>();
  stmts.push_back(must(parse_statement));
  return make<Block>(stmts);
}

If* Parser::parse_if()
{
  consume(IF);
  consume(OPEN_PAREN);
  auto expr = must(parse_expr);
  consume(CLOSE_PAREN);
  auto block = must(parse_optional_block);
  if (!match(ELSE))
    return make<If>(expr, block);
  return make<If>(expr, block, must(parse_optional_block));
}

VarDecl* Parser::parse_decl()
{
  consume(LET);
  auto var = must(parse_var);
  if (match(COLON)) {
    auto typ = must(parse_type);
    if (match(OP, Operator::ASSIGN)) {
      consume(OP, Operator::ASSIGN);
      auto expr = must(parse_expr);
      return make<VarDecl>(var, typ, expr);
    }
    return make<VarDecl>(var, typ);
  }
  return make<VarDecl>(var);
}

Result<ExpressionList> parse_args()
{
  auto ok = consume(OPEN_PAREN);
  if (!ok) {
    return ok.takeError();
  }
  auto args = make<ExpressionList>();
  while (1) {
    auto arg = parse_expr();
    if (!arg) {
      return arg.takeError();
    }
    args.emplace_back(std::move(*arg));
    // This structure allows for a trailing comma in the argument list in order
    // to be formatted nicely. But it does not allow for arbitrary commas.
    if (!match(COMMA))
      break;
    auto ok = consume(COMMA);
    if (!ok) {
      return ok.takeError();
    }
  }
  ok = consume(CLOSE_PAREN);
  if (!ok) {
    return ok.takeError();
  }
  return args;
}

Result<Expression> Parser::parse_var()
{
  auto maybeName = consume(VAR);
  if (!maybeName) {
    return maybeName.takeError();
  }
  auto name = *maybeName;

  // Positional parameters, e.g. '$1', as well as associated meta
  // parameters, e.g. '$#', are all processed here based on just the
  // name of the variable.
  if (is_positional_parameter(name)) {
    return make<PositionalParameter>(name);
  }

  return make<Var>(name);
}

Result<Map*> Parser::parse_map()
{
  auto name = consume(MAP);

  // Maps are special and require the index expression to be parsed
  // right here. It will be stored with the `Map` AST node directly.
  if (match(LEFT_BRACKET)) {
    consume(LEFT_BRACKET);
    auto key_expr = must(parse_expr);
    consume(RIGHT_BRACKET);
    return make<Map>(name, key_expr);
  } else {
    return make<Map>(name);
  }
}

std::variant<Expression, SizedType> Parser::parse_primary_expr()
{
  if (match(OPEN_PAREN)) {
    consume(OPEN_PAREN);
    auto r = must(parse_expr_type);
    consume(CLOSE_PAREN);
    return r;
  }

  if (match(OP, Operator::MUL)) {
    auto op = consume(OP);
    auto r = must(parse_expr_type);
    if (std::holds_variant<SizedType>(r)) {
      return CreatePointer(*std::get<SizedType>(&r));
    }
    return Unop(op, std::get<Expression&>(&r));
  }

  // From here it had better contain an actual expression, and not a type.
  std::optional<Expression&> expr;
  switch (tokenizer_.current_token()) {
    case VAR:
      expr = must(parse_var);
    case MAP:
      expr = must(parse_map);
    case IDENT:
      auto name = consume(IDENT);
      // See if this is a call to determine whether we need to express
      // this as a builtin variable or as a call.
      if (match(OPEN_PAREN)) {
        expr = make<Call>(name, must(parse_args));
      } else {
        expr = make<Builtin>(name);
      }
    case OP: {
      auto op = consume(OP);
      switch (op) {
        case Operator::INCREMENT:
        case Operator::DECREMENT:
          return Unop(op, must(parse_expr));

        case Operator::MUL:
        case Operator::BNOT:
        case Operator::LNOT:
        case Operator::MINUS:
          return Binop(op, must(parse_expr));
        default:
          fail() << "unknown operator " << op;
      }
    }
    default:
      fail() << "unexpected token during expression";
  }

  return make<Expression>();
}

std::variant<Expression&, SizedType> Parser::parse_expr_type()
{
  // Always see if this can be parsed directly as a type first, prior to
  // recursing into a full expression. This *may* fail, and the `parse_type`
  // method is guaranteed to leave the tokens untouched.
  auto typ = parse_type();
  if (typ) {
    return *typ;
  }

  // If it does not match a type, then parse as a full expression.
  return parse_expr();
}

Expression Parser::parse_expr()
{
  bool was_paren = match(OPEN_PAREN);
  auto last = parse_primary_expr();
  bool is_paren = match(OPEN_PAREN);

  // If the last expression is a type, then we have a cast. We require either
  // the type or the next expression to be in a parenthesis, so we don't accept
  // something like `int32 5` as a cast.
  if (std::holds_alternative<SizedType>(last)) {
    if (!was_paren && !is_paren)
      fail() << "did you mean to put parenthesis for this cast?";
    auto &last_type = std::get<SizedType>(last);
    auto r = parse_expr();
    if (!r) {
      return r.takeError();
    }
    return ast_.make_node<Cast>(std::move(last_type), std::move(*r), position());
  }

  // The first term was a primary expression.
  auto &last_expr = std::get<Expression>(last);
  switch (tokenizer_.current_token()) {
    case QUESTION:
      auto true_cond = must(parse_expr);
      consume(COLON);
      auto false_cond = must(parse_expr);
      return make<Tenary>(last, true_cond, false_cond);
    case DOT:
      consume(DOT);
      if (match(INT)) {
        auto n = consume(INT);
        return make<FieldAccess>(last, n);
      } else if (match(IDENT)) {
        auto name = consume(IDENT);
        return make<FieldAccess>(last, name);
      } else {
        fail() << "unknown field type following '.'";
        return last_expr;
      }
    case OPEN_BRACKET:
      consume(OPEN_BRACKET);
      last = make<ArrayAccess>(last, parse_expr());
      consume(CLOSE_BRACKET);
    case QUESTION:
      auto t = must<parse_expr>();
      if (!t) {
        return t.takeError();
      }
      auto ok = consume(COLON);
      if (!ok) {
        return ok.takeError();
      }
      auto f = must<parse_expr>();
      if (!f) {
         return f.takeError();
      }
      return ast_.make_node<Ternary>(last_expr, *t, *f, position());
    case OP:
      // Check if this is a compound op.
      auto op = parse_compound_op(current_token_contents());
      if (op) {
        require<Var, Map>(last, "assignment operator used without variable");
        last = make<AssignVar>(last, make<Binop>(last, parse_expr()));
        break;
      }
      auto op = consume<Operator>(OP);
      switch (op) {
        case Operator::ASSIGN:
          require<Var, Map>(last);
          last = make<AssignVar>(last, parse_expr());
          break;
        case Operator::INCREMENT:
        case Operator::DECREMENT:
          if (last) {
            last = Unop(op,
                        require<Var, Map>(last),
                        /*is_postop=*/true);
          } else {
            auto var = parse_var();
            last = Unop(op, var, /*is_postop=*/false);
          }
          break;
        case Operator::MUL:
        case Operator::BNOT:
        case Operator::LNOT:
        case Operator::MINUS:
          if (last) {
            last = Binop(op, last, parse_expr());
          } else {
            last = Unop(op, parse_expr());
          }
          break;
      }
  }
}

} // namespace bpftrace::ast
