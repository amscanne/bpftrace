#pragma once

#include <memory>
#include <ostream>

#include "ast/visitor.h"

namespace bpftrace::ast {

// BufferState is an internal type.
struct BufferState;

// Buffer is an internal type for output construction.
class Buffer {
public:
  Buffer();
  ~Buffer() = default;

  Buffer& append(Buffer&& other);
  Buffer& text(std::string str);
  Buffer& comment(std::string str);
  Buffer& line_break();

private:
  std::unique_ptr<BufferState> state;
};

// Buffer is directly printable, used below.
std::ostream &operator<<(std::ostream &out, const Buffer &buffer);

// Generic class for printing AST nodes.
//
// This class is specialized for each AST node type, but the implementation
// is in printer.cpp.
template <typename T>
class Formatter {
public:
  Buffer format(const T &value, MetadataIndex metadata,
            std::optional<size_t> max_width = std::nullopt);

  template <typename U>
    requires (!std::is_same_v<T, U>)
  Buffer format(const U &value, MetadataIndex metadata,
            std::optional<size_t> max_width = std::nullopt)
  {
    return Formatter<U>().format(value, metadata, max_width);
  }
};

// Printer is a class to format AST nodes of type T.
class Printer : Visitor<Printer, Buffer> {
public:
  enum Mode {
    Normal, // Print with full comments and spacing.
    Debug,  // Print with no comments, spacing but full types.
  };
  Printer(ASTContext &ast, std::ostream &out, Mode mode = Normal, std::optional<size_t> max_width = std::nullopt)
      : ast_(ast), out_(out), mode_(mode), max_width_(max_width) {};
  void emit(std::function<void(Buffer &)> fn);

  template <typename T>
  void visit(T &value)
  {
    emit([&](Buffer &buffer) {
      Formatter<T>(buffer, ast_.metadata(), max_width_).format(value);
    });
  }

private:
  ASTContext &ast_;
  std::ostream &out_;
  Mode mode_;
  std::optional<size_t> max_width_;
};

} // namespace bpftrace::ast
