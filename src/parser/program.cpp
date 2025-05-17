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

Result<ast::Program*> Parser::parse()
{
  // Parsing a complete BPF trace program is really parsing multiple different
  // grammars together. We read the full file, but switch over to walking
  // through configuration statement, using the dedicated attachpoint parser,
  // or using the script parser for the body of probes and macros.
  std::stringstream c_definitions;
  std::optional<Config&> config;
  SubprogList functions;
  ProbeList probes;

  while (true) {
    if (match(Token::END)) {
      break;
    } else if (match(Token::HASH)) {
      // The full line matches whenver it starts with a hash. This is a special
      // case in the tokenizer, which essentially matches '#[^ !].*$'.
      c_definitions << consume(HASH) << "\n";
    } else if (matchAll(IDENT, "struct") || matchAll(IDENT, "union") ||
               matchAll(IDENT, "enum")) {
      // Inline C structure definitions.
      while (!match(Token::OPEN_BRACKET)) {
        c_definitions << " " << consume();
      }
      c_definitions << must(parse_definition);
    } else if (matchAll(IDENT, "config")) {
      // If we match the configuration block, match sure we didn't parse one
      // already and then parse it here. We will continue to parse it anyways,
      // but the compiler will fail.
      if (config.has_value())
        fail() << "multiple configuration blocks found";
      config.emplace(must(parse_config));
    } else if (matchAll(IDENT, "fn")) {
      // Parse a subprogram definition.
      subprogs.push_back(must(parse_subprog));
    } else {
      // Other things encountered at the top-level will be processed as a probe
      // definition.
      probes.push_back(must(parse_probe))
    }
  }

  return make<Program>(
      c_definitions.str(), config, std::move(functions), std::move(probes));
}

} // namespace bpftrace::parser
