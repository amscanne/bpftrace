#pragma once

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "ast/pass_manager.h"

namespace bpftrace::ast {

class Bitcode {
public:
  std::vector<std::unique_ptr<llvm::Module>> modules;
  std::vector<std::string> objects;
};

class BPFBitcode : public State<"bpf-bitcode">, public Bitcode {};
class HostBitcode : public State<"host-bitcode">, public Bitcode {};

class ClangBuildError : public ErrorInfo<ClangBuildError> {
public:
  static char ID;
  void log(llvm::raw_ostream &OS) const override;
  ClangBuildError(std::string msg) : msg_(std::move(msg)) {};

private:
  std::string msg_;
};

ast::Pass CreateClangBuildBPFPass();
ast::Pass CreateClangBuildHostPass();

} // namespace bpftrace::ast
