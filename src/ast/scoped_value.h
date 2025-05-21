#pragma once

#include <llvm/Config/llvm-config.h>
#include <llvm/IR/IRBuilder.h>
#include <optional>
#include <variant>

namespace bpftrace::ast {

using namespace llvm;

// ScopedValue ties SSA values to some lifetime, and distinguishes between
// potential L-values and R-values for a given type. This allows temporary
// values to be returned with scope-bound lifetimes, and temporary copies
// between memory addresses to be avoided where possible.
//
// Note that the load and free functions provided should be portable; if they
// are special (requiring the use of some helper function), then note that they
// may be used transitively on r-values nested within the original r-value and
// should take into consideration the types.
class ScopedValue {
public:
  ~ScopedValue();
  ScopedValue &operator=(ScopedValue &&other) = delete;
  ScopedValue(const ScopedValue &other) = delete;
  ScopedValue &operator=(const ScopedValue &other) = delete;

  using loadfn_t = std::function<llvm::Value *(llvm::Value *)>;
  using freefn_t = std::function<void(llvm::Value *)>;
  using boundfn_t = std::function<void(void)>;

  // Provide an explicit l-value, and function that produces an rvalue.
  explicit ScopedValue(Value *lvalue, loadfn_t load, freefn_t free);

  // Provide an l-value, which is also the r-value. Code that operates on this
  // will just need to know how to unpack these types. This is effectively the
  // `tvalue`, where the address is managed but can't be accessed.
  explicit ScopedValue(Value *lvalue, freefn_t free);

  // Provide an explicit r-value, and no associated l-value.
  explicit ScopedValue(Value *rvalue);

  // Provide a transformation of an existing `ScopedValue`. This preserves the
  // original memory location, but changes the transform that is applied on
  // load. If it is an r-value, then it is applied immediately.
  explicit ScopedValue(ScopedValue &&other, loadfn_t transform);

  // Returns the rvalue, or nullptr if there is none.
  Value *rvalue();

  // Returns the lvalue, or nullptr if there is none.
  Value *lvalue();

  // May be used to disable the deletion method, essentially leaking some
  // memory within the frame. The use of this function should be generally
  // considered a bug, as it will make dealing with larger functions and
  // multiple scopes more problematic over time.
  void disarm();

private:
  // Just the value.
  using rvalue_t = llvm::Value *;
  // The address, a load and release function.
  using lvalue_t = std::tuple<llvm::Value *, loadfn_t, freefn_t>;
  // The transformed value, and a release function.
  using tvalue_t = std::tuple<llvm::Value *, boundfn_t>;

  std::variant<rvalue_t, lvalue_t, tvalue_t> value_;
};

} // namespace bpftrace::ast
