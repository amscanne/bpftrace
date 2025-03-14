#pragma once

#include <ostream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ast/ast.h"
#include "ast/location.h"
#include "ast/symbol.h"
#include "types.h"

namespace bpftrace {

// A parameter for a BpfScript function
class Param {
public:
  Param(std::string name, SizedType type)
      : name_(std::move(name)), type_(std::move(type))
  {
  }

  const std::string &name() const
  {
    return name_;
  }
  const SizedType &type() const
  {
    return type_;
  }

private:
  std::string name_;
  SizedType type_;
};

// Represents the type of a function which is callable in a BpfScript program.
//
// The function's implementation is not contained here.
class Function {
public:
  using Symbol = ast::Symbol;

  // "Builtin" functions are hardcoded into bpftrace.
  // "Script" functions are user-defined in BpfScript.
  // "External" functions are imported from pre-compiled BPF programs.
  enum class Origin {
    Builtin,
    Script,
    External,
  };

  Function(Origin origin,
           Symbol symbol,
           SizedType return_type,
           const std::vector<Param> &params)
      : symbol_(std::move(symbol)),
        return_type_(std::move(return_type)),
        params_(params),
        origin_(origin)
  {
  }

  const Symbol &symbol() const
  {
    return symbol_;
  }
  const SizedType &return_type() const
  {
    return return_type_;
  }
  const std::vector<Param> &params() const
  {
    return params_;
  }
  Origin origin() const
  {
    return origin_;
  }

private:
  Symbol symbol_;
  SizedType return_type_;
  std::vector<Param> params_;
  Origin origin_;
};

// Registry of callable functions
//
// Non-builtin functions are not allowed to share the same name. When a builtin
// and a non-builtin function share a name, the non-builtin is preferred.
class FunctionRegistry {
public:
  using Symbol = ast::Symbol;

  const Function *add(Function::Origin origin,
                      Symbol symbol,
                      const SizedType &return_type,
                      const std::vector<Param> &params);

  // Returns the best match for the given function name and arguments.
  const Function *get(Symbol symbol,
                      const std::vector<SizedType> &arg_types,
                      const ast::Node &node) const;

private:
  std::unordered_map<Symbol, std::vector<std::reference_wrapper<const Function>>>
      funcs_by_symbol_;
  std::vector<std::unique_ptr<Function>> all_funcs_;
};

} // namespace bpftrace
