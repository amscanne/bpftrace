#include <cassert>
#include <sstream>

#include "tokenizer/ops.h"
#include "tokenizer/position.h"
#include "tokenizer/tokenizer.h"
#include "util/int_parser.h"

namespace bpftrace::tokenizer {

std::ostream &operator<<(std::ostream &os, const Operator &op)
{
  switch (op) {
    case Operator::INVALID:
      os << "[invalid]";
      break;
    case Operator::ASSIGN:
      os << "=";
      break;
    case Operator::EQ:
      os << "==";
      break;
    case Operator::NE:
      os << "!=";
      break;
    case Operator::LE:
      os << "<=";
      break;
    case Operator::GE:
      os << ">=";
      break;
    case Operator::LEFT:
      os << "<<";
      break;
    case Operator::RIGHT:
      os << ">>";
      break;
    case Operator::LT:
      os << "<";
      break;
    case Operator::GT:
      os << ">";
      break;
    case Operator::LAND:
      os << "&&";
      break;
    case Operator::LOR:
      os << "||";
      break;
    case Operator::PLUS:
      os << "+";
      break;
    case Operator::INCREMENT:
      os << "++";
      break;
    case Operator::DECREMENT:
      os << "--";
      break;
    case Operator::MINUS:
      os << "-";
      break;
    case Operator::MUL:
      os << "*";
      break;
    case Operator::DIV:
      os << "/";
      break;
    case Operator::MOD:
      os << "%";
      break;
    case Operator::BAND:
      os << "&";
      break;
    case Operator::BOR:
      os << "|";
      break;
    case Operator::BXOR:
      os << "^";
      break;
    case Operator::LNOT:
      os << "!";
      break;
    case Operator::BNOT:
      os << "~";
      break;
  }
  return os;
}

std::ostream &operator<<(std::ostream &os, const Token &token)
{
  os << token.type_;
  std::visit(
      [&os](auto &&arg) {
        if constexpr (!std::is_same_v<std::decay_t<decltype(arg)>,
                                      std::monostate>) {
          os << "(" << arg << ")";
        }
      },
      token.contents_);
  return os;
}

std::ostream &operator<<(std::ostream &os, const Token::Type &typ)
{
  switch (typ) {
    case Token::INTEGER:
      os << "INTEGER";
      break;
    case Token::STRING:
      os << "STRING";
      break;
    case Token::IDENT:
      os << "IDENT";
      break;
    case Token::VAR:
      os << "VAR";
      break;
    case Token::MAP:
      os << "MAP";
      break;
    case Token::COMMA:
      os << "COMMA";
      break;
    case Token::OP:
      os << "OP";
      break;
    case Token::QUESTION:
      os << "QUESTION";
      break;
    case Token::COLON:
      os << "COLON";
      break;
    case Token::SEMI_COLON:
      os << "SEMI_COLON";
      break;
    case Token::OPEN_BRACE:
      os << "OPEN_BRACE";
      break;
    case Token::CLOSE_BRACE:
      os << "CLOSE_BRACE";
      break;
    case Token::OPEN_BRACKET:
      os << "OPEN_BRACKET";
      break;
    case Token::CLOSE_BRACKET:
      os << "CLOSE_BRACKET";
      break;
    case Token::OPEN_PAREN:
      os << "OPEN_PAREN";
      break;
    case Token::CLOSE_PAREN:
      os << "CLOSE_PAREN";
      break;
    case Token::END:
      os << "END";
      break;
    case Token::UNKNOWN:
      os << "UNKNOWN";
      break;
  }
  return os;
}

char Tokenizer::readChar()
{
  auto in = get();
  if (in == '\n') {
    position_.end_line++;
    position_.end_column = 1;
    lines_.emplace_back(current_line_.str());
    current_line_.str(std::string());
  } else {
    position_.end_column++;
    current_line_ << in;
  }
  return in;
}

std::string Tokenizer::readInteger()
{
  readChar();
  return "";
}

std::string Tokenizer::readString()
{
  std::stringstream ss;

  auto start = readChar();
  assert(start == '"');

  while (true) {
    auto in = readChar();
    switch (in) {
      case '"':
        return ss.str();
      case '\\': {
        auto s = readChar();
        switch (s) {
          case 'a':
            ss << "\a";
            break;
          case 'b':
            ss << "\b";
            break;
          case 't':
            ss << "\t";
            break;
          case 'n':
            ss << "\n";
            break;
          case 'v':
            ss << "\v";
            break;
          case 'f':
            ss << "\f";
            break;
          case 'r':
            ss << "\r";
            break;
          case 'e':
            ss << "\e";
            break;
          case '"':
            ss << "\"";
            break;
          case '\'':
            ss << "\'";
            break;
          case '?':
            ss << "\?";
            break;
          case '\\':
            ss << "\\";
            break;
          case '\n':
            break; // Skip the break.
          default:
            // N.B. unicode not supported.
            if (s == 'x') {
              int value = 0;
              int digits = 0;
              s = readChar();
              while (digits <= 2) {
                if (s >= '0' && s <= '9')
                  value += s - '0';
                else if (s >= 'a' && s <= 'f')
                  value += 10 + s - 'a';
                else if (s >= 'A' && s <= 'F')
                  value += 10 + s - 'A';
                digits++;
                s = readChar();
              }
              ss << static_cast<char>(value);
            } else if (s >= '0' && s <= '7') {
              int value = 0;
              int digits = 0;
              while (digits <= 3 && s >= '0' && s <= '7') {
                value += 8 * (s - '0');
                digits++;
                s = readChar();
              }
              ss << static_cast<char>(value);
            } else {
              // Pass through the literal.
              ss << "\\" << s;
            }
            break;
        }
        break;
      }
      default:
        ss << in;
        break;
    }
  }

  return ss.str();
}

std::string Tokenizer::readIdentifier()
{
  std::stringstream ss;

  while (true) {
    // We must peek as technically the "empty" identifier is valid for e.g.
    // maps. This will be called when hitting a '@' for example.
    auto in = peek();
    if (in >= 'a' && in <= 'z') {
      ss << in;
    } else if (in >= 'A' && in <= 'Z') {
      ss << in;
    } else if (in >= '0' && in <= '9') {
      ss << in;
    } else if (in == '_') {
      ss << in;
    } else {
      return ss.str();
    }
    readChar(); // Advance.
  }
}

Token Tokenizer::readToken()
{
  while (true) {
    auto in = peek();
    if (in < 0)
      return { Token::Token::END, "<EOF>" };

    // Advance the ranges to reset the token position.
    position_.start_line = position_.end_line;
    position_.start_column = position_.end_column;

    if (in == ' ' || in == '\t' || in == '\r' || in == '\n') {
      readChar();
      continue; // Keep iterating.
    }
    if (in == '"') {
      return { Token::STRING, readString() };
    }
    if ((in >= 'a' && in <= 'z') || (in >= 'A' && in <= 'Z') || in == '_') {
      return { Token::IDENT, readIdentifier() };
    }
    if (in >= '0' && in <= '9') {
      return { Token::INTEGER, readInteger() };
    }

    // Commit and read the character.
    in = readChar();
    switch (in) {
      case '$':
        return { Token::VAR, "$" + readIdentifier() };
      case '@':
        return { Token::MAP, "@" + readIdentifier() };
      case '=':
        if (peek() == '=') {
          readChar();
          return { Token::OP, Operator::EQ };
        }
        return { Token::OP, Operator::ASSIGN };
      case '!':
        if (peek() == '=') {
          readChar();
          return { Token::OP, Operator::NE };
        }
        return { Token::OP, Operator::LNOT };
      case '+':
        if (peek() == '+') {
          readChar();
          return { Token::OP, Operator::INCREMENT };
        }
        return { Token::OP, Operator::PLUS };
      case '-':
        if (peek() == '-') {
          readChar();
          return { Token::OP, Operator::DECREMENT };
        }
        return { Token::OP, Operator::MINUS };
      case '&':
        if (peek() == '&') {
          readChar();
          return { Token::OP, Operator::LAND };
        }
        return { Token::OP, Operator::BAND };
      case '%':
        return { Token::OP, Operator::MOD };
      case '|':
        if (peek() == '|') {
          readChar();
          return { Token::OP, Operator::LOR };
        }
        return { Token::OP, Operator::BOR };
      case '*':
        return { Token::OP, Operator::MUL };
      case '<':
        if (peek() == '=') {
          readChar();
          return { Token::OP, Operator::LE };
        }
        if (peek() == '<') {
          readChar();
          return { Token::OP, Operator::LEFT };
        }
        return { Token::OP, Operator::LT };
      case '>':
        if (peek() == '=') {
          return { Token::OP, Operator::GE };
        }
        if (peek() == '>') {
          readChar();
          return { Token::OP, Operator::RIGHT };
        }
        return { Token::OP, Operator::GT };
      case '/':
        if (peek() == '/') {
          readChar();
          // Record the comment as in. The parser may choose to use this in the
          // future, but it is outside the regular token stream.
          std::stringstream ss;
          while ((in = readChar()) != '\n') {
            ss << in;
          }
          comments_.emplace_back(ss.str());
          break; // Resume the loop.
        }
        if (peek() == '*') {
          readChar();
          // See above; record the comment as is.
          std::stringstream ss;
          while ((in = readChar()) != '*' || peek() != '/') {
            ss << in;
          }
          comments_.emplace_back(ss.str());
          break; // Resume above.
        }
        return { Token::OP, Operator::DIV };
      case '~':
        return { Token::OP, Operator::BNOT };
      case '^':
        return { Token::OP, Operator::BXOR };
      case '#': {
        if (peek() == '!' && position_.start_line == 1 &&
            position_.start_column == 1) {
          while (readChar() != '\n') {
          }
          break;
        }
        // Read until a line break.
        std::stringstream ss;
        while ((in = readChar()) != '\n') {
          ss << in;
        }
        comments_.emplace_back(ss.str());
        break; // Resume.
      }
      case '?':
        return { Token::QUESTION, "?" };
      case ',':
        return { Token::COMMA, "," };
      case ':':
        return { Token::COLON, ":" };
      case ';':
        return { Token::SEMI_COLON, ";" };
      case '{':
        return { Token::OPEN_BRACE, "{" };
      case '}':
        return { Token::CLOSE_BRACE, "}" };
      case '[':
        return { Token::OPEN_BRACKET, "[" };
      case ']':
        return { Token::CLOSE_BRACKET, "]" };
      case '(':
        return { Token::OPEN_PAREN, "(" };
      case ')':
        return { Token::CLOSE_PAREN, ")" };
      default:
        // This will not be handled by the parser, meaning that it will
        // ultimately generate an error at the right place.
        const char contents[] = { in, '\0' };
        return { Token::UNKNOWN, contents };
    }
  }
}

} // namespace bpftrace::tokenizer
