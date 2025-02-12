#pragma once

#include <cassert>
#include <string>
#include <sstream>
#include <variant>
#include <vector>

#include "location.hh"

namespace bpftrace {
namespace ast {

// Diag is a syntactic helper for constructing a diagnostic. This is basically
// a stringstream that can be implicitly converted to a full diagnostic.
class Diag {
public:
  Diag(const location loc) : loc_(loc)
  {
  }
  template <typename T>
  Diag& operator<<(const T& t)
  {
    ss_ << t;
    return *this;
  }
private:
  std::stringstream ss_;
  const location loc_;
  friend class Diagnostic;
};

// Diagnostic reflects a single error at a single source location. This is a
// simple wrapper around a string for that message, and the location class.
class Diagnostic {
public:
  Diagnostic(std::string &&msg) : msg_(std::move(msg))
  {
  }
  Diagnostic(std::string &&msg, const location loc) : msg_(msg), loc_(loc)
  {
  }
  Diagnostic(Diag& ds) : msg_(ds.ss_.str()), loc_(ds.loc_)
  {
  }
  const std::string& msg() { return msg_; }
  const std::optional<location>& loc() { return loc_; }
private:
  std::string msg_;
  std::optional<location> loc_;
};

using Diagnostics = std::vector<Diagnostic>;

// ErrorOr wraps a concrete result or a list of errors. It is always capable of
// carrying a list of warnings as well, although this requires some boilerplate.
//
// Suppose we have `foo`, which returns `ErrorOr<int>` and `bar`, which returns
// `ErrorOr<bool>`, then the recommended way of using the class is as follows:
//
//   ErrorOr<int> foo() {
//     auto b = bar();
//     if (!b.ok()) {
//       return b; // Can't proceed without it.
//     }
//
//     // Option A:
//     Diagnostics warnings;
//     bool val = b.unwrap(warnings); // Collects all warnings.
//     // Use val here...
//
//     // Option B:
//     auto [val, warnings] = b.unwrap();
//     // Use val here...
//
//     return {(int)val, std::move(warnings)};
//   }
template <typename T>
class ErrorOr {
public:
  // Value without any warnings.
  ErrorOr(T &&t) : result_(std::move(t))
  {
  }
  // Value and warnings.
  ErrorOr(T &&t, Diagnostics &&w) : result_(std::move(t)), warnings_(std::move(w))
  {
  }
  // Single diagnostic error.
  ErrorOr(Diagnostic &&err) : result_(Diagnostics{std::move(err)})
  {
  }
  // Multiple diagnostic errors.
  ErrorOr(Diagnostics &&errs) : result_(std::move(errs))
  {
  }
  // Errors and warnings.
  ErrorOr(Diagnostics &&errs, Diagnostics &&w) : result_(std::move(errs)), warnings_(std::move(w))
  {
  }
  // Consuming two others of the same type; this is fine, we aggregate all
  // errors and warnings from both, and take the first value.
  ErrorOr(ErrorOr<T> &&first, ErrorOr<T> &&second) : result_(std::move(first.result_)), warnings_(std::move(first.warnings_))
  {
    // Does the second also have an error? Need to aggregate. We can't do
    // anything in the case of two values, this just needs to be handled by the
    // user. But we can make diagnostic aggregation super simple.
    if (ok() && !second.ok()) {
      result_ = std::move(second.errors());
    } else if(!ok && !second.ok()) {
      auto &errs = errors();
      auto &other = second.errors();
      errs.insert(errs.end(), other.begin(), other.end());
    }
    // Aggregate warnings.
    warnings_.insert(warnings_.end(), second.warnings_.begin(), second.warnings_.end());
  }
  template <typename U>
  ErrorOr(const ErrorOr<U>& other) : result_(std::get<Diagnostics>(other.result_)), warnings_(other.warnings_)
  {
    assert(!other.ok());
  }
  template <typename U>
  ErrorOr(const ErrorOr<U>& other, Diagnostics &&w) : ErrorOr(other)
  {
    // Append the extra diagnostics.
    warnings_.insert(warnings_.end(), w.begin(), w.end());
  }

  bool ok() const {
    return std::holds_alternative<T>(result_);
  }
  T&& unwrap(Diagnostics &warnings) {
    assert(ok());
    warnings.insert(warnings.end(), warnings_.begin(), warnings_.end());
    return std::move(std::get<T>(result_));
  }
  std::pair<T&&, Diagnostics&&> unwrap() {
    assert(ok());
    return {std::move(std::get<T>(result_)), std::move(warnings_)};
  }
  const Diagnostics& errors() {
    assert(!ok());
    return std::get<Diagnostics>(result_);
  }
  const Diagnostics& warnings() {
    return warnings_;
  }

private:
  std::variant<T, Diagnostics> result_;
  Diagnostics warnings_;

  template <typename U>
  friend class ErrorOr;
};

// Note that to simplify the types above, we just have a monostate value. This
// means that `unwrap` et al can continue to work without needing special
// handling around void, although the result is not going to be interesting.
using ErrorOrSuccess = ErrorOr<std::monostate>;

inline ErrorOrSuccess Success() {
  return ErrorOrSuccess(std::monostate{});
}

inline ErrorOrSuccess Success(Diagnostics &&w) {
  return ErrorOrSuccess(std::monostate{}, std::move(w));
}

inline ErrorOrSuccess Failure(std::string &&msg) {
  return ErrorOrSuccess(Diagnostic(std::move(msg)));
}

} // namespace ast
} // namespace bpftrace
