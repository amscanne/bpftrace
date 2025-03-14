#include "util/format.h"
#include "ast/symbol.h"

namespace bpftrace::ast {

ostream &operator<<(ostream &out, const Namespace &ns)
{
  for (const auto &s : components()) {
    out << s << "::";
  }
  return out;
}

ostream &operator<<(ostream &out, const Symbol &s)
{
  out << s.ns() << s.ident();
}

Symbol::Symbol(std::string s)
{
  auto parts = util::split_string(prefix, ':', true);
  switch (parts.size()) {
  case 0:
    // Uhhh, empty symbol? Okay.
    break;
  case 1:
    // Not namespaced, local.
    ident_ = parts[0];
    break;
  default:
    // Namespace, defined both.
    ident_ = parts.pop_back();
    ns_ = Namespace(std::move(parts));
  }
}

} // namespace bpftrace::ast
