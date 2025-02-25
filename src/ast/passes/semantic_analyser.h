#pragma once

#include "ast/ast.h"
#include "ast/pass_manager.h"

namespace bpftrace::ast {

class Semantics : public ast::State<"semantics"> {
public:
  // Represents the assignment of special call values to specific maps.
  std::unordered_map<std::reference_wrapper<ast::Call>,
                     std::reference_wrapper<ast::Map>>
      map_assignments_;
};

Pass CreateSemanticPass(bool listing = false);

} // namespace bpftrace::ast
