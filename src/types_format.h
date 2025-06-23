#pragma once

#include "bpftrace.h"
#include "output/output.h"
#include "types.h"
#include "util/result.h"

namespace bpftrace {

// TypeFormatError means that the type is not convertible.
//
// This should never happen.
class TypeFormatError : public ErrorInfo<TypeFormatError> {
public:
  TypeFormatError(SizedType &ty) : ty_(ty) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  SizedType ty_;
};

// format is responsible for translating from a `SizedType` value,
// pointed at by `data` (with `sz` bytes), into an `output::Value`
// that can be printed by the output plugin.
Result<output::Value> format(BPFtrace &bpf,
                             const SizedType &ty,
                             const std::vector<uint8_t> &value,
                             bool is_per_cpu,
                             uint32_t div);

} // namespace bpftrace
