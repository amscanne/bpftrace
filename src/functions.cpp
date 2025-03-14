#include "functions.h"

namespace bpftrace {

namespace {
std::string arg_types_str(const std::vector<SizedType> &arg_types)
{
  std::string str = "(";
  bool first = true;
  for (const SizedType &arg_type : arg_types) {
    if (!first)
      str += ", ";
    str += typestr(arg_type);
    first = false;
  }
  str += ")";
  return str;
}

std::string param_types_str(const std::vector<Param> &params)
{
  std::string str = "(";
  bool first = true;
  for (const Param &param : params) {
    if (!first)
      str += ", ";
    str += typestr(param.type());
    first = false;
  }
  str += ")";
  return str;
}
} // namespace

const Function *FunctionRegistry::add(Function::Origin origin,
                                      Symbol symbol,
                                      const SizedType &return_type,
                                      const std::vector<Param> &params)
{
  // Check for duplicate function definitions
  // The assumption is that builtin functions are all added to the registry
  // before any user-defined functions.
  // Builtin functions can be duplicated. Other functions can not.
  for (const Function &func : funcs_by_symbol_[symbol]) {
    if (func.origin() != Function::Origin::Builtin) {
      return nullptr;
    }
  }

  all_funcs_.push_back(std::make_unique<Function>(
      origin, std::string{ name }, return_type, params));
  Function &new_func = *all_funcs_.back().get();

  funcs_by_symbol_[symbol].emplace_back(new_func);
  return &new_func;
}

namespace {
bool can_implicit_cast(const SizedType &from, const SizedType &to)
{
  if (from.FitsInto(to))
    return true;

  if (from.IsStringTy() && to.IsPtrTy() && to.GetPointeeTy()->IsIntTy() &&
      to.GetPointeeTy()->GetSize() == 1) {
    // Allow casting from string to int8* or uint8*
    return true;
  }

  // Builtin and script functions do not care about string sizes. External
  // functions cannot be defined to accept string types (they'd take char*)
  if (from.IsStringTy() && to.IsStringTy())
    return true;

  return false;
}
} // namespace

// Find the best function by symbol for the given argument types.
//
// Returns either a single function or nullptr, when no such function exists.
//
// When there are multiple candidate functions with the same name, prefer the
// non-builtin over the builtin function.
//
// Valid functions have the correct name and all arguments can be implicitly
// casted into all parameter types.
const Function *FunctionRegistry::get(Symbol symbol,
                                      const std::vector<SizedType> &arg_types,
                                      const ast::Node &node) const
{
  auto it = funcs_by_symbol_.find(symbol);
  if (it == funcs_by_symbol_.end()) {
    node.addError() << "Function not found: '" << symbol << "'";
    return nullptr;
  }

  const auto &candidates = it->second;

  // We disallow duplicate functions other than for builtins, so expect at most
  // two exact matches.
  assert(candidates.size() <= 2);

  // No candidates => no match
  // 1 candidate   => use it
  // 2 candidates  => use non-builtin candidate
  const Function *candidate = nullptr;
  for (const Function &func : candidates) {
    candidate = &func;
    if (candidate->origin() != Function::Origin::Builtin)
      break;
  }

  // Validate that the candidate's parameters can take our arguments
  if (candidate) {
    bool valid = true;
    if (candidate->params().size() != arg_types.size()) {
      valid = false;
    } else {
      for (size_t i = 0; i < arg_types.size(); i++) {
        if (!can_implicit_cast(arg_types[i], candidate->params()[i].type())) {
          valid = false;
          break;
        }
      }
    }

    if (valid)
      return candidate;
  }

  auto &err = node.addError();
  err << "Cannot call function '" << symbol
      << "' using argument types: " << arg_types_str(arg_types);
  err.addHint() << "Candidate function:\n  " << candidate->symbol()
                << param_types_str(candidate->params());

  return nullptr;
}

} // namespace bpftrace
