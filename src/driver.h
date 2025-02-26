#pragma once

#include "ast/context.h"
#include "bpftrace.h"

typedef void *yyscan_t;

#define YY_DECL                                                                \
  bpftrace::Parser::symbol_type yylex(bpftrace::Driver &driver,                \
                                      yyscan_t yyscanner)

namespace bpftrace {

class Parser;

class Driver {
public:
  explicit Driver(ast::ASTContext &ctx,
                  std::map<std::string, std::string> &macros,
                  bool listing,
                  bool debug);
  void parse(const std::string &source);
  void error(const location &l, const std::string &m);

  // These are accessible to the parser and lexer, but are not mutable.
  ast::ASTContext &ctx;
  const std::map<std::string, std::string> &macros;
  const bool listing;
  const bool debug;
};

} // namespace bpftrace
