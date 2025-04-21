#pragma once

#include "parser/tokenizer.h"
#include "parser/position.h"

namespace bpftrace::parser {

// ParseError is a generic parse error.
class ParseError : public ErrorInfo<ParseError> {
public:
  static char ID;
  ParseError(std::string &&s) : s_(std::move(s)) {};
  void log(llvm::raw_ostream &OS) const override {
    OS << s;
  }
private:
  std::string s;
};

// BaseParser is a generic parser.
class BaseParser {
public:
  BaseParser(Tokenizer &tokenizer) : tokenizer(tokenizer) {
    positions_.push_back(tokenizer_.current().position());
  };

  // match functions check the next token in sequence. The `matchAny` and
  // `matchAll` are provided as a convenience, which can check against the
  // token types or token values.
  template <typename T>
  bool match(T value)
  {
    if constexpr (std::is_same_v<T, Type>) {
      return tokenizer_.current().type() == value;
    } else {
      return tokenizer_.current().contents<T>() == value;
    }
  }
  template <typename... Args>
  bool matchAny(Args... args)
  {
    return false || (match(args) || ...);
  }
  template <typename... Args>
  bool matchAll(Args... args)
  {
    return true && (match(args) && ...);
  }

  // consume is used to actually match and consume the next token. This is
  // preferred path for generating errors, as they will automatically include
  // the current token and the set of expected token types. The token contents
  // will be returned.
  //
  // If a more detailed error is needed, then a manual match should be done,
  // with the associated manual fail.
  template <typename R = OK, TokenType T, typename... Args>
  Result<R> consume(T arg, Args... args)
  {
    bool type_ok = matchAll(arg);
    bool vals_ok = matchAny(std::forward<Args>(args)...);
    if (!type_ok || !vals_ok) {
      std::stringstream ss;
      if (!type_ok) {
        ss << "unexpected token";
      } else if (!vals_ok) {
        ss << " expected " << join(std::forward<Args>(args)...);
      }
    }
    return consume<R>();
  }
  template <typename R = OK>
  Result<R> consume()
  {
    if constexpr (std::is_same_v<R, OK>) {
      tokenizer_.advance();
      return OK();
    } else {
      auto rval = tokenizer_.current().contents<R>();
      tokenizer_.advance();
      return rval;
    }
  }

private:
  Tokenizer &tokenizer_;
  std::vector<Position> positions_;
};

// Parser parses top-level programs.
//
// In the future this will be split into parts that allow parsing just function
// bodies, etc.
class Parser {
};

} // namespace parser
} // namespace bpftrace
