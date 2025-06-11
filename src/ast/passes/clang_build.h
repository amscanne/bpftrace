#pragma once

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "ast/pass_manager.h"

namespace bpftrace::ast {

class BPFModule {
public:
  BPFModule(std::unique_ptr<llvm::LLVMContext> &&ctx,
            std::unique_ptr<llvm::Module> &&mod,
            std::string &&object)
      : ctx(std::move(ctx)), mod(std::move(mod)), object(std::move(object)) {};

  std::unique_ptr<llvm::LLVMContext> ctx;
  std::unique_ptr<llvm::Module> mod;
  std::string object;
};

class HostModule {
public:
  HostModule(std::unique_ptr<llvm::LLVMContext> &&ctx,
             std::unique_ptr<llvm::Module> &&mod)
      : ctx(std::move(ctx)), mod(std::move(mod)) {};

  std::unique_ptr<llvm::LLVMContext> ctx;
  std::unique_ptr<llvm::Module> mod;
};

class BitcodeModules : public State<"bitcode"> {
public:
  std::vector<BPFModule> bpf;
  std::vector<HostModule> host;
};

class ClangBuildError : public ErrorInfo<ClangBuildError> {
public:
  static char ID;
  void log(llvm::raw_ostream &OS) const override;
  ClangBuildError(std::string msg) : msg_(std::move(msg)) {};

private:
  std::string msg_;
};

ast::Pass CreateClangBuildPass();

} // namespace bpftrace::ast
