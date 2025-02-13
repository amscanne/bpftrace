#pragma once

#include "ast/pass_manager.h"
#include "ast/visitor.h"

namespace bpftrace {
namespace ast {

class ReturnPathAnalyser : public Visitor<ReturnPathAnalyser, bool> {
public:
  // visit methods return true iff all return paths of the analyzed code
  // (represented by the given node) return a value
  // For details for concrete node type see the implementations
  using Visitor<ReturnPathAnalyser, bool>::visit;
  bool visit(Program &prog);
  bool visit(Subprog &subprog);
  bool visit(Jump &jump);
  bool visit(If &if_stmt);

  std::string error()
  {
    return err_.str();
  }

private:
  std::ostringstream err_;
};

Pass CreateReturnPathPass(std::ostream &out = std::cerr);

} // namespace ast
} // namespace bpftrace
