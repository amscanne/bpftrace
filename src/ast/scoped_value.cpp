#include "ast/scoped_value.h"

namespace bpftrace::ast {

ScopedValue::ScopedValue(Value *lvalue, loadfn_t load, freefn_t free)
    : value_(std::make_tuple(lvalue, load, free))
{
}

ScopedValue::ScopedValue(Value *lvalue, freefn_t free)
    : value_(
          std::make_tuple(lvalue, loadfn_t([](Value *v) { return v; }), free))
{
}

ScopedValue::ScopedValue(Value *rvalue) : value_(rvalue)
{
}

ScopedValue::ScopedValue(Value *rvalue, ScopedValue &&other)
{
  if (std::holds_alternative<lvalue_t>(other.value_)) {
    // We lose the ability to reference directly as an l-value, since the
    // transformation is not necessarily reversible. This binds the free
    // function to the original location value.
    auto &[v, load, free] = std::get<lvalue_t>(other.value_);
    value_.emplace<tvalue_t>(std::make_tuple(rvalue, [v, free]() { free(v); }));
  } else if (std::holds_alternative<tvalue_t>(other.value_)) {
    // We just apply another transformation.
    auto &[v, free] = std::get<tvalue_t>(other.value_);
    value_.emplace<tvalue_t>(std::make_tuple(rvalue, free));
  } else {
    // Just transform the value directly.
    value_.emplace<rvalue_t>(rvalue);
  }
  // Clear the other version.
  other.value_.emplace<rvalue_t>(nullptr);
}

ScopedValue::ScopedValue(Value *lvalue, loadfn_t load, ScopedValue &&other)
{
  if (std::holds_alternative<lvalue_t>(other.value_)) {
    // Replace the load function, and bind the free function.
    auto &[v, orig_load, free] = std::get<lvalue_t>(other.value_);
    value_.emplace<lvalue_t>(
        std::make_tuple(lvalue, load, [v, free](llvm::Value *) { free(v); }));
  } else if (std::holds_alternative<tvalue_t>(other.value_)) {
    // Just carry over the bound release function.
    auto &[v, free] = std::get<tvalue_t>(other.value_);
    value_.emplace<lvalue_t>(
        std::make_tuple(lvalue, load, [free](llvm::Value *) { free(); }));
  } else {
    // Just set as a regular l-value.
    value_.emplace<lvalue_t>(lvalue, load, [](llvm::Value *) {});
  }
  // Clear the other version.
  other.value_.emplace<rvalue_t>(nullptr);
}

ScopedValue::ScopedValue(ScopedValue &&other) : value_(std::move(other.value_))
{
  other.value_.emplace<rvalue_t>(nullptr);
}

void ScopedValue::destroy()
{
  if (std::holds_alternative<lvalue_t>(value_)) {
    auto &[v, _, free] = std::get<lvalue_t>(value_);
    free(v);
  } else if (std::holds_alternative<tvalue_t>(value_)) {
    auto &[_, free] = std::get<tvalue_t>(value_);
    free();
  }
  value_.emplace<rvalue_t>(nullptr);
}

ScopedValue &ScopedValue::operator=(ScopedValue &&other)
{
  destroy();
  value_ = std::move(other.value_);
  other.value_.emplace<rvalue_t>(nullptr);
  return *this;
}

ScopedValue::~ScopedValue()
{
  destroy();
}

Value *ScopedValue::rvalue()
{
  if (std::holds_alternative<lvalue_t>(value_)) {
    auto &[v, load, _] = std::get<lvalue_t>(value_);
    return load(v);
  } else if (std::holds_alternative<tvalue_t>(value_)) {
    auto &[v, _] = std::get<tvalue_t>(value_);
    return v;
  } else {
    return std::get<rvalue_t>(value_);
  }
}

Value *ScopedValue::lvalue()
{
  if (std::holds_alternative<lvalue_t>(value_)) {
    auto &[v, load_, free_] = std::get<lvalue_t>(value_);
    return v;
  } else {
    return nullptr;
  }
}

void ScopedValue::disarm()
{
  value_.emplace<rvalue_t>(rvalue());
}

} // namespace bpftrace::ast
