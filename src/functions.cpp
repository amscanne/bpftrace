#include "functions.h"

#include <ranges>

#include "log.h"

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
    if (param.type().IsNoneTy()) {
      str += "T";
    } else {
      str += typestr(param.type());
    }
    first = false;
  }
  str += ")";
  return str;
}
} // namespace

const Function *FunctionRegistry::add(Function::Origin origin,
                                      std::string_view ns,
                                      std::string_view name,
                                      const SizedType &return_type,
                                      const std::vector<Param> &params,
				      bool varargs)
{
  FqName fq_name{
    .ns = std::string{ ns },
    .name = std::string{ name },
  };

  // Check for duplicate function definitions. The assumption is that builtin
  // functions are all added to the registry before any user-defined functions.
  // Builtin functions can be duplicated. Other functions can not.
  for (const Function &func : funcs_by_fq_name_[fq_name]) {
    if (func.origin() != Function::Origin::Builtin) {
      return nullptr;
    }
  }

  all_funcs_.push_back(std::make_unique<Function>(
      origin, std::string{ name }, return_type, params, varargs));
  Function &new_func = *all_funcs_.back().get();

  // Note that the order is important here, as we will search from back to
  // front to ensure that user-defined functions are referenced first.
  funcs_by_fq_name_[fq_name].push_back(new_func);
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

/*
 * Find the best function by name for the given argument types.
 *
 * Returns either a single function or nullptr, when no such function exists.
 *
 * When there are multiple candidate functions with the same name, prefer the
 * non-builtin over the builtin function.
 *
 * Valid functions have the correct name and all arguments can be implicitly
 * casted into all parameter types.
 */
const Function *FunctionRegistry::get(std::string_view ns,
                                      std::string_view name,
                                      const std::vector<SizedType> &arg_types,
                                      std::ostream &out,
                                      std::optional<location> loc) const
{
  FqName fq_name = {
    .ns = std::string{ ns },
    .name = std::string{ name },
  };
  auto it = funcs_by_fq_name_.find(fq_name);
  if (it == funcs_by_fq_name_.end()) {
    LOG(ERROR, loc, out) << "Function not found: '" << name << "'";
    return nullptr;
  }

  // Find the candidates from the set of available functions. If the function
  // defined is a user-defined function, then we don't match against builtin
  // candidates (shadowing is complete).
  const auto &candidates = it->second;
  auto search_order = std::views::reverse(candidates);
  std::vector<std::reference_wrapper<const Function>> considered;
  for (const Function &candidate : search_order) {
    considered.push_back(candidate);
    bool is_builtin = candidate.origin() == Function::Origin::Builtin;

    // Validate that the candidate's parameters can take our arguments. Note
    // that *iff* the function is a builtin, we treat a none type as a generic
    // type.  It may be possible to generalize this in the future and support
    // this for user-defined functions, but for now this is a special feature
    // of builtins that have custom code generation (but we want to rely on the
    // function registry for type checking, at least).
    bool valid = true;
    auto params = candidate.params();
    auto check_args = arg_types.size();
    if (params.size() != check_args) {
      if (candidate.varargs() && check_args >= params.size()) {
        check_args = params.size();
      } else {
	check_args = 0;
        valid = false;
      }
    }
    for (size_t i = 0; i < check_args; i++) {
      if (is_builtin && params[i].type().IsNoneTy()) {
        continue; // Generic parameter, see above.
      }
      if (!can_implicit_cast(arg_types[i], params[i].type())) {
        valid = false;
        break;
      }
    }
    if (valid)
      return &candidate;

    // See above: shadowing for user-defined functions is complete.
    if (!is_builtin)
      return nullptr;
  }

  LOG(ERROR, loc, out) << "Cannot call function '" << name
                       << "' using argument types: "
                       << arg_types_str(arg_types);
  for (const Function &func : considered) {
    LOG(HINT, out) << "Candidate function:\n  " << func.name()
                   << param_types_str(func.params());
  }

  return nullptr;
}

} // namespace bpftrace
