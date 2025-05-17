#pragma once

#include "ast/ast.h"
#include "tokenizer/tokenizer.h"
#include "util/result.h"

namespace bpftrace::parser {

// Parse a full bpftrace program.
Result<ast::Program *> parse_program(ASTContext &ast, tokenizer::Tokenizer &tok);

} // namespace bpftrace::parser
