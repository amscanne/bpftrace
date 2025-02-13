#pragma once

#include <iostream>
#include <sstream>

#include "ast/pass_manager.h"
#include "ast/visitor.h"

namespace bpftrace {
namespace ast {

// Checks if a script uses any non-portable bpftrace features that AOT
// cannot handle.
//
// Over time, we expect to relax these restrictions as AOT supports more
// features.
class PortabilityAnalyser : public Visitor<PortabilityAnalyser> {
public:
  using Visitor<PortabilityAnalyser>::visit;
  void visit(PositionalParameter &param);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Cast &cast);
  void visit(AttachPoint &ap);

  std::string error()
  {
    return err_.str();
  }

private:
  std::ostringstream err_;
};

Pass CreatePortabilityPass(std::ostream &out = std::cerr);

} // namespace ast
} // namespace bpftrace
