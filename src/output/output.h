#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace bpftrace::output {

// Primitive is a basic value.
//
// This covers basic atoms, arrays, structures, etc.
//
// It does not cover any advanced maps.
struct Primitive {
  using Variant = std::variant<bool,
                               int64_t,
                               uint64_t,
                               double,
                               std::string,
                               std::vector<Primitive>,
                               std::map<std::string, Primitive>>;

  template <typename T>
  Primitive(T t) : variant(t){};

  const Variant variant;
};

// Histogram is a basic histogram.
//
// It is up to the output engine how to display this.
struct Histogram {
  std::vector<Primitive> labels;
  std::vector<uint64_t> counts;
};

// Value is an arbitrary value.
//
// This is a primitive, or a high-level histogram or map over
// another arbitrary value.
struct Value {
  using Variant =
      std::variant<Histogram, Primitive, std::map<Primitive, Value>>;

  template <typename T>
  Value(T t) : variant(t){};

  const Variant variant;
};

// Abstract class for output.
//
// This should be overriden by individual implementations.
class Output {
public:
  virtual ~Output() = default;

  virtual void map(const std::string &name, bool scalar, const Value &value);
  virtual void value(const Value &value);
  virtual void - hist, -stats, -printf, -time, -cat, -join, -syscall,
      -attached_probes, -lost_events, -helper_error,
};

} // namespace bpftrace::output
