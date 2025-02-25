#pragma once

#include <variant>

#include "ast/diagnostic.h"

namespace bpftrace::ast {

class Node {
public:
  Node(Diagnostics &d, Location &&loc) : diagnostics_(d), loc(loc) {};
  virtual ~Node() = default;

  Node(const Node &) = delete;
  Node &operator=(const Node &) = delete;
  Node(Node &&) = delete;
  Node &operator=(Node &&) = delete;

  template <typename... Args>
  Diagnostic &addError(Args &...args) const
  {
    if constexpr (sizeof...(Args) == 0) {
      return diagnostics_.addError(loc);
    } else {
      return diagnostics_.addError(loc + (args.loc + ...));
    }
  }
  template <typename... Args>
  Diagnostic &addWarning(Args &...args) const
  {
    if constexpr (sizeof...(Args) == 0) {
      return diagnostics_.addWarning(loc);
    } else {
      return diagnostics_.addWarning(loc + (args.loc + ...));
    }
  }

private:
  Diagnostics &diagnostics_;

public:
  const Location loc;
};

template <typename... Ts>
class Variant {
public:
  // For simplicity, allow virtual nodes to be default constructible and
  // effectively hold no specific type.
  using variant_t = std::variant<std::monostate, std::reference_wrapper<Ts>...>;
  Variant(variant_t value) : value_(std::move(value)) {};
  Variant() = default;

  template <typename T>
  bool is() const
  {
    return std::holds_alternative<std::reference_wrapper<T>>(value_);
  }

  template <typename T>
  T &as() const
  {
    return std::get<std::reference_wrapper<T>>(value_);
  }

  // Returns the type erased reference, which can be used to extract the
  // location, add diagnostics, etc.
  Node &node()
  {
    return std::visit(
        [](const auto &v) -> Node & {
          if constexpr (std::is_same_v<std::decay_t<decltype(v)>,
                                       std::monostate>) {
            assert(false);
            __builtin_unreachable();
          } else {
            return v;
          }
        },
        value());
  }

  // Returns the type-rich variant, which is used to walk, etc.
  variant_t &value()
  {
    return value_;
  }

  const variant_t &value() const
  {
    return value_;
  }

private:
  variant_t value_;
};

} // namespace bpftrace::ast
