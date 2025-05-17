#pragma once

#include "ast/ast.h"
#include "ast/context.h"
#include "tokenizer/tokenizer.h"
#include "util/result.h"

namespace bpftrace::parser {

// Parse a standard bpfscript expression.
Result<ast::Expression> parse_expr(ASTContext &ast, tokenizer::Tokenizer &tok);

// Parse a full bpftrace block. Note that the first token must be an open
// brace, and parsing will stop after the final matching brace.
Result<ast::Block *> parse_block(ASTContext &ast, tokenizer::Tokenizer &tok);

} // namespace bpftrace::parser
