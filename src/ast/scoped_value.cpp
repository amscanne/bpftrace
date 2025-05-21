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

ScopedValue::ScopedValue(ScopedValue &&other, loadfn_t transform)
{
  if (std::holds_alternative<lvalue_t>(other.value_)) {
    // We lose the ability to reference directly as an l-value, since the
    // transformation is not necessarily reversible.
    auto &[v, load, free] = std::get<lvalue_t>(other.value_);
    value_.emplace<tvalue_t>(
        std::make_tuple(transform(load(v)), [v, free]() { free(v); }));
  } else if (std::holds_alternative<tvalue_t>(other.value_)) {
    // We just apply another transformation.
    auto &[v, free] = std::get<tvalue_t>(other.value_);
    value_.emplace<tvalue_t>(std::make_tuple(transform(v), free));
  } else {
    // Just transform the value directly.
    value_.emplace<rvalue_t>(transform(std::get<rvalue_t>(other.value_)));
  }
  // Clear the other version.
  other.value_.emplace<rvalue_t>(nullptr);
}

ScopedValue::~ScopedValue()
{
  if (std::holds_alternative<lvalue_t>(value_)) {
    auto &[v, _, free] = std::get<lvalue_t>(value_);
    free(v);
  } else if (std::holds_alternative<tvalue_t>(value_)) {
    auto &[_, free] = std::get<tvalue_t>(value_);
    free();
  }
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
  value_.emplace<rvalue_t>(lvalue());
}

} // namespace bpftrace::ast
