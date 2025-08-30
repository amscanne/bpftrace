#include <fstream>
#include <unordered_map>

#include "ast/ast.h"
#include "ast/passes/clang_build.h"
#include "ast/passes/type_system.h"

namespace bpftrace::ast {

Pass CreateTypeSystemPass()
{
  auto fn = [](BitcodeModules &bm) -> Result<TypeMetadata> {
    TypeMetadata result;

    // Load all kernel types.
    std::string kernel_btf_source = "/sys/kernel/btf/vmlinux";
    std::ifstream kernel_btf(kernel_btf_source);
    if (!kernel_btf.is_open()) {
      return make_error<SystemError>("Unable to read " + kernel_btf_source);
    }
    auto kernel_btf_data = std::string(std::istreambuf_iterator<char>(kernel_btf),
                                std::istreambuf_iterator<char>());
    auto kernel_types = btf::Types::parse(static_cast<const void*>(kernel_btf_data.data()), kernel_btf_data.size());
    if (!kernel_types) {
      return kernel_types.takeError();
    }
    auto aggregate = std::move(*kernel_types); // Initial type set.

    // For now, we simply build a single type system that covers all the
    // external imports and standard library. In theory, this should be rebased
    // on top of the individual probe type system (coming from the kernel,
    // module or user binary).
    for (const auto &s : bm.objects) {
      auto btf = btf::Types::parse(static_cast<const void *>(s.data()),
                                   s.size());
      if (!btf) {
        return btf.takeError();
      }
      auto ok = aggregate.append(*btf);
      if (!ok) {
        return ok.takeError();
      }
    }
    result.global = std::move(aggregate);
    return result;
  };

  return Pass::create("TypeSystem", fn);
}

Pass CreateDumpTypesPass(std::ostream &out)
{
  auto fn = [&out](TypeMetadata &tm) {
    for (const auto &type : tm.global) {
      if (!type.is<btf::Function>()) {
        continue;
      }
      out << type.as<btf::Function>() << "\n";
    }
    for (const auto &type : tm.global) {
      if (!type.is<btf::Var>()) {
        continue;
      }
      out << type.as<btf::Var>() << "\n";
    }
  };
  return Pass::create("DumpTypes", fn);
}

} // namespace bpftrace::ast
