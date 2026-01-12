#pragma once

#include "ast/pass_manager.h"
#include "btf/btf.h"

namespace bpftrace::ast {

// Macros loaded from include files, etc.
class ExternalTypes : public ast::State<"external-types"> {
public:
  // Generated BTF for all included & defined types.
  btf::Types types;
};

class TypesError : public ErrorInfo<TypesError> {
public:
  TypesError() = default;
  explicit TypesError(std::string message) : message_(std::move(message)) {}

  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string message_;
};

ast::Pass CreateDefineExternalTypesPass(const std::vector<std::string> &extra_flags = {});

} // namespace bpftrace::ast
