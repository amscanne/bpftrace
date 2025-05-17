#pragma once

#include <cassert>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include "tokenizer/ops.h"
#include "tokenizer/position.h"

namespace bpftrace::tokenizer {

// A stream of tokens is the output from the tokenizer.
//
// Each token has a type associated with it, defined by the Type enum. Each
// token may also carry some content with it, so it is generally useful to keep
// these types as broad as possible, for structural parsing decisions, and
// allow the parser or later stages to infer more detailed information.
class Token {
public:
  enum Type {
    INTEGER,
    STRING,
    IDENT,
    VAR,
    MAP,
    COMMA,
    OP,
    QUESTION,
    COLON,
    SEMI_COLON,
    OPEN_BRACE,
    CLOSE_BRACE,
    OPEN_BRACKET,
    CLOSE_BRACKET,
    OPEN_PAREN,
    CLOSE_PAREN,
    UNKNOWN,
    END,
  };

  Token(Type t) : type_(t)
  {
  }
  Token(Type t, std::string &&c) : type_(t), contents_(std::move(c))
  {
  }
  Token(Type t, const char *c) : type_(t), contents_(std::string(c))
  {
  }
  Token(Type t, Operator op) : type_(t), contents_(op)
  {
  }
  Token(Type t, uint64_t val) : type_(t), contents_(val)
  {
  }
  Token(Type t, int64_t val) : type_(t), contents_(val)
  {
  }

  // Returns the token type.
  Type type() const
  {
    return type_;
  }

  // Returns the token position.
  const Position& position() const
  {
    return position_;
  }

  // Returns the token contents.
  template <typename T>
  const T &contents() const
  {
    auto ptr = std::get_if<T>(&contents_);
    assert(ptr);
    return *ptr;
  }

private:
  Type type_;
  std::variant<std::monostate, std::string, Operator, uint64_t, int64_t>
      contents_;
  Position position_;
  friend std::ostream &operator<<(std::ostream &os, const Token &token);
  friend std::ostream &operator<<(std::ostream &os, const Type &typ);
  friend class Tokenizer;
};

// Tokenizer is an abstraction that allows different token sources.
class Tokenizer {
public:
  Tokenizer() : current_(Token::END)
  {
    advance();
  }

  // Returns the current token.
  const Token &current()
  {
    return current_;
  }

  // Advances to the next token.
  void advance()
  {
    current_ = readToken();
    current_.position_ = position_;
  }

  // Returns and flushes the set of comments processed since comments was last
  // called. This is not considered part of the stream of tokens.
  std::vector<std::string> comments()
  {
    return std::move(comments_);
  }

private:
  char readChar();
  std::string readString();
  std::string readIdentifier();
  std::string readInteger();

  virtual Token readToken();
  virtual char peek() = 0;
  virtual char get() = 0;

  Position position_;
  Token current_;
  std::vector<std::string> comments_;
  std::stringstream current_line_;
  std::vector<std::string> lines_;
};

// FileTokenizer operates on an input stream and produces a sequence of tokens.
class FileTokenizer : public Tokenizer {
public:
  FileTokenizer(std::ifstream &input) : input_(input) {};

private:
  char peek() override
  {
    return input_.peek();
  }
  char get() override
  {
    return input_.get();
  }

  std::ifstream &input_;
};

// StringTokenizer operatoes on an input string.
class StringTokenizer : public Tokenizer {
public:
  StringTokenizer(const std::string &str)
  {
    ss_.str(str);
  }

private:
  char peek() override
  {
    return ss_.peek();
  }
  char get() override
  {
    return ss_.get();
  }

  std::stringstream ss_;
};

} // namespace bpftrace::tokenizer
