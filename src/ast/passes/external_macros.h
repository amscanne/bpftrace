#pragma once

#include "ast/pass_manager.h"
#include <map>

namespace bpftrace::ast {

// Macros loaded from include files, etc.
class ExternalMacros : public ast::State<"external-macros"> {
public:
  // Map of macro name to macro definition.
  std::map<std::string, std::string> macros;
};

class MacroError : public ErrorInfo<MacroError> {
public:
  MacroError() = default;
  explicit MacroError(std::string message) : message_(std::move(message)) {}

  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string message_;
};

ast::Pass CreateDefineExternalMacrosPass(const std::vector<std::string> &extra_flags = {});
ast::Pass CreateExpandExternalMacrosPass();

} // namespace bpftrace::ast
