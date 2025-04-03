#pragma once

#include <bcc/bcc_usdt.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/IR/IRBuilder.h>
#include <optional>

#include "ast/ast.h"
#include "ast/async_ids.h"
#include "bpftrace.h"
#include "types.h"

#define CREATE_ATOMIC_RMW(op, ptr, val, align, order)                          \
  CreateAtomicRMW((op), (ptr), (val), MaybeAlign((align)), (order))

namespace bpftrace::ast {

using namespace llvm;

class IRBuilderBPF;

// ScopedValue ties SSA values to some lifetime, and distinguishes between
// potential L-values and R-values for a given type.
//
// This allows temporary values to be returned with scope-bound lifetimes, and
// temporary copies between memory addresses to be avoided where possible.
class ScopedValue {
public:
  using loadfn_t = std::function<llvm::Value *(llvm::Value *)>;
  using freefn_t = std::function<void(llvm::Value *)>;
  using boundfn_t = std::function<void(void)>;

  // Provide an explicit l-value, and function that produces an rvalue.
  explicit ScopedValue(Value *lvalue, loadfn_t load, freefn_t free)
      : value_(std::make_tuple(lvalue, load, free)){};

  // Provide an l-value, which is also the r-value. Code that operates on this
  // will just need to know how to unpack these types. This is effectively the
  // `tvalue`, where the address is managed but can't be accessed.
  explicit ScopedValue(Value *lvalue, freefn_t free)
      : value_(std::make_tuple(lvalue,
                               loadfn_t([](Value *v) { return v; }),
                               free)){};

  // Provide an explicit r-value, and no associated l-value.
  explicit ScopedValue(Value *rvalue) : value_(rvalue){};

  // Provide a transformation of an existing `ScopedValue`. This preserves the
  // original memory location, but changes the transform that is applied on
  // load. If it is an r-value, then it is applied immediately.
  explicit ScopedValue(ScopedValue &&other, loadfn_t transform)
  {
    if (std::holds_alternative<lvalue_t>(other.value_)) {
      // We lose the ability to reference directly as an l-value, since the
      // transformation is not necessarily reversible.
      auto &[v, load, free] = std::get<lvalue_t>(other.value_);
      value_.emplace<tvalue_t>(
          std::make_tuple(transform(load(v)), [v, free]() { free(v); }));
    } else if (std::holds_alternative<tvalue_t>(other.value_)) {
      // We just apply another transformation.
      auto &[v, free] = std::get<tvalue_t>(other.value_);
      value_.emplace<tvalue_t>(std::make_tuple(transform(v), free));
    } else {
      // Just transform the value directly.
      value_.emplace<rvalue_t>(transform(std::get<rvalue_t>(other.value_)));
    }
    // Clear the other version.
    other.value_.emplace<rvalue_t>(nullptr);
  }

  ScopedValue &operator=(ScopedValue &&other) = delete;
  ScopedValue(const ScopedValue &other) = delete;
  ScopedValue &operator=(const ScopedValue &other) = delete;

  ~ScopedValue()
  {
    if (std::holds_alternative<lvalue_t>(value_)) {
      auto &[v, _, free] = std::get<lvalue_t>(value_);
      free(v);
    } else if (std::holds_alternative<tvalue_t>(value_)) {
      auto &[_, free] = std::get<tvalue_t>(value_);
      free();
    }
  }

  Value *rvalue()
  {
    if (std::holds_alternative<lvalue_t>(value_)) {
      auto &[v, load, _] = std::get<lvalue_t>(value_);
      return load(v);
    } else if (std::holds_alternative<tvalue_t>(value_)) {
      auto &[v, _] = std::get<tvalue_t>(value_);
      return v;
    } else {
      return std::get<rvalue_t>(value_);
    }
  }

  Value *lvalue()
  {
    if (std::holds_alternative<lvalue_t>(value_)) {
      auto &[v, load_, free_] = std::get<lvalue_t>(value_);
      return v;
    } else {
      return nullptr;
    }
  }

  // May be used to disable the deletion method, essentially leaking some
  // memory within the frame. The use of this function should be generally
  // considered a bug, as it will make dealing with larger functions and
  // multiple scopes more problematic over time.
  void disarm()
  {
    value_.emplace<rvalue_t>(lvalue());
  }

private:
  // Just the value.
  using rvalue_t = llvm::Value *;
  // The address, a load and release function.
  using lvalue_t = std::tuple<llvm::Value *, loadfn_t, freefn_t>;
  // The transformed value, and a release function.
  using tvalue_t = std::tuple<llvm::Value *, boundfn_t>;

  std::variant<rvalue_t, lvalue_t, tvalue_t> value_;
};

class IRBuilderBPF : public IRBuilder<> {
public:
  IRBuilderBPF(LLVMContext &context,
               Module &module,
               BPFtrace &bpftrace,
               AsyncIds &async_ids);

  // Allocation helpers.
  ScopedValue CreateAllocaBPF(llvm::Type *ty, const std::string &name = "");
  ScopedValue CreateAllocaBPF(const SizedType &stype,
                              const std::string &name = "");
  ScopedValue CreateAllocaBPF(int bytes, const std::string &name = "");

  // Memset & memcpy helpers.
  void CreateMemsetBPF(Value *ptr, Value *val, uint32_t size);
  void CreateMemcpyBPF(Value *dst, Value *src, uint32_t size);

  // Type helpers.
  llvm::Type *GetType(const SizedType &stype, bool emit_codegen_types = true);
  llvm::Type *GetMapValueType(const SizedType &stype);
  llvm::ConstantInt *GetIntSameSize(uint64_t C, llvm::Value *expr);
  llvm::ConstantInt *GetIntSameSize(uint64_t C, llvm::Type *ty);
  Value *GetMapVar(const std::string &map_name);
  Value *GetNull();

  // CreateMapLookup optionally takes a function which will provide the initial
  // value for the map. This affects the type of lookup; if this is not
  // provided, then the lookup will not insert on lookup value, and a null
  // value will be returned. If this value is provided, then the map lookup
  // will insert the element if it is not present.
  ScopedValue CreateMapLookup(
      Value *ctx,
      const std::string &map_name,
      Value *key,
      SizedType &type,
      const Location &loc,
      std::optional<std::function<ScopedValue(void)>> init = std::nullopt);

  Value *CreatePerCpuMapAggElems(Value *ctx,
                                 Map &map,
                                 Value *key,
                                 const SizedType &type,
                                 const Location &loc);
  void CreateMapUpdateElem(Value *ctx,
                           const std::string &map_ident,
                           Value *key,
                           Value *val,
                           const Location &loc,
                           int64_t flags = 0);
  void CreateMapDeleteElem(Value *ctx,
                           Map &map,
                           Value *key,
                           const Location &loc);
  Value *CreateForEachMapElem(Value *ctx,
                              Map &map,
                              Value *callback,
                              Value *callback_ctx,
                              const Location &loc);
  void CreateProbeRead(Value *ctx,
                       Value *dst,
                       llvm::Value *size,
                       Value *src,
                       AddrSpace as,
                       const Location &loc);

  // Emits a bpf_probe_read call in which the size is derived from the SizedType
  // argument. Has special handling for certain types such as pointers where the
  // size depends on the host system as well as the probe type.
  //
  // The addrress space must be specified, and must be either kernel or user.
  void CreateProbeRead(Value *ctx,
                       Value *dst,
                       const SizedType &type,
                       Value *src,
                       AddrSpace addrSpace,
                       const Location &loc);

  CallInst *CreateProbeReadStr(Value *ctx,
                               Value *dst,
                               Value *size,
                               Value *src,
                               AddrSpace as,
                               const Location &loc);

  Value *CreateUSDTReadArgument(Value *ctx,
                                AttachPoint *attach_point,
                                int usdt_location_index,
                                int arg_num,
                                Builtin &builtin,
                                std::optional<pid_t> pid,
                                AddrSpace as,
                                const Location &loc);

  Value *CreateStrncmp(Value *str1, Value *str2, uint64_t n, bool inverse);
  Value *CreateStrcontains(Value *haystack,
                           uint64_t haystack_sz,
                           Value *needle,
                           uint64_t needle_sz);
  Value *CreateIntegerArrayCmp(Value *ctx,
                               Value *val1,
                               Value *val2,
                               const SizedType &val1_type,
                               const SizedType &val2_type,
                               bool inverse,
                               const Location &loc,
                               MDNode *metadata);

  // Helpers that return literal values.
  CallInst *CreateGetNs(TimestampMode ts, const Location &loc);
  CallInst *CreateJiffies64(const Location &loc);
  CallInst *CreateGetCurrentCgroupId(const Location &loc);
  CallInst *CreateGetUidGid(const Location &loc);
  CallInst *CreateGetNumaId(const Location &loc);
  CallInst *CreateGetCpuId(const Location &loc);
  CallInst *CreateGetCurrentTask(const Location &loc);
  CallInst *CreateGetRandom(const Location &loc);
  CallInst *CreateGetFuncIp(Value *ctx, const Location &loc);
  CallInst *CreatePerCpuPtr(Value *var, Value *cpu, const Location &loc);
  CallInst *CreateThisCpuPtr(Value *var, const Location &loc);
  CallInst *CreateGetJoinMap(BasicBlock *failure_callback, const Location &loc);
  CallInst *CreateGetStackScratchMap(StackType stack_type,
                                     BasicBlock *failure_callback,
                                     const Location &loc);

  CallInst *CreateGetStack(Value *ctx,
                           bool ustack,
                           Value *buf,
                           StackType stack_type,
                           const Location &loc);

  // Allocation helpers. The returned `ScopedValue` will be an l-value.
  Value *CreateGetStrAllocation(const std::string &name, const Location &loc);
  Value *CreateGetFmtStringArgsAllocation(StructType *struct_type,
                                          const std::string &name,
                                          const Location &loc);
  Value *CreateTupleAllocation(const SizedType &tuple_type,
                               const std::string &name,
                               const Location &loc);
  Value *CreateWriteMapValueAllocation(const SizedType &value_type,
                                       const std::string &name,
                                       const Location &loc);
  Value *CreateVariableAllocationInit(const SizedType &value_type,
                                      const std::string &name,
                                      const Location &loc);
  Value *CreateMapKeyAllocation(const SizedType &value_type,
                                const std::string &name,
                                const Location &loc);

  void CreateCheckSetRecursion(const Location &loc, int early_exit_ret);
  void CreateUnSetRecursion(const Location &loc);
  CallInst *CreateCall(FunctionType *callee_type,
                       Value *callee,
                       ArrayRef<Value *> args,
                       const Twine &Name);
  void CreateGetCurrentComm(Value *ctx,
                            AllocaInst *buf,
                            size_t size,
                            const Location &loc);
  void CreateOutput(Value *ctx, Value *data, size_t size, const Location &loc);
  void CreateAtomicIncCounter(const std::string &map_name, uint32_t idx);
  void CreateMapElemInit(Value *ctx,
                         Map &map,
                         Value *key,
                         Value *val,
                         const Location &loc);
  void CreateMapElemAdd(Value *ctx,
                        Map &map,
                        Value *key,
                        Value *val,
                        const Location &loc);
  void CreateDebugOutput(std::string fmt_str,
                         const std::vector<Value *> &values,
                         const Location &loc);
  void CreateTracePrintk(Value *fmt,
                         Value *fmt_size,
                         const std::vector<Value *> &values,
                         const Location &loc);
  void CreateSignal(Value *ctx, Value *sig, const Location &loc);
  void CreateOverrideReturn(Value *ctx, Value *rc);
  void CreateHelperError(Value *ctx,
                         Value *return_value,
                         libbpf::bpf_func_id func_id,
                         const Location &loc);
  void CreateHelperErrorCond(Value *ctx,
                             Value *return_value,
                             libbpf::bpf_func_id func_id,
                             const Location &loc,
                             bool compare_zero = false);
  StructType *GetStackStructType(bool is_ustack);
  StructType *GetStructType(std::string name,
                            const std::vector<llvm::Type *> &elements,
                            bool packed = false);
  Value *CreateGetPid(const Location &loc);
  Value *CreateGetTid(const Location &loc);
  Value *CreateGetPid(Value *ctx, const Location &loc);
  Value *CreateGetTid(Value *ctx, const Location &loc);
  ScopedValue CreateUSym(Value *ctx,
                         Value *val,
                         int probe_id,
                         const Location &loc);
  Value *CreateRegisterRead(Value *ctx, const std::string &builtin);
  Value *CreateRegisterRead(Value *ctx, int offset, const std::string &name);
  Value *CreateKFuncArg(Value *ctx, SizedType &type, std::string &name);
  Value *CreateRawTracepointArg(Value *ctx, const std::string &builtin);
  Value *CreateUprobeArgsRecord(Value *ctx, const SizedType &args_type);
  llvm::Type *UprobeArgsType(const SizedType &args_type);

  ScopedValue CreateSkbOutput(ScopedValue &&skb,
                              ScopedValue &&len,
                              ScopedValue &&data,
                              size_t size);

  void CreatePath(Value *ctx,
                  Value *buf,
                  Value *path,
                  Value *sz,
                  const Location &loc);
  void CreateSeqPrintf(Value *ctx,
                       Value *fmt,
                       Value *fmt_size,
                       Value *data,
                       Value *data_len,
                       const Location &loc);

  // For a type T, creates an integer expression representing the byte offset
  // of the element at the given index in T[]. Used for array dereferences and
  // pointer arithmetic.
  llvm::Value *CreatePtrOffset(const SizedType &type,
                               llvm::Value *index,
                               AddrSpace as);

  // Safely handle pointer references by wrapping the address with the
  // intrinsic `preserve_static_offset` [1], which will ensure that LLVM does
  // not apply certain basic optimizations (notably, saving any intermediate
  // offset from this pointer). This is required for the context pointer,
  // which, if modified. will trigger an error in the verifier. This method
  // also automatically handles casts from integers and other pointers; the
  // output value is always a pointer to `ty`.
  //
  // [1] https://reviews.llvm.org/D133361
  llvm::Value *CreateSafeGEP(llvm::Type *Ty,
                             llvm::Value *Ptr,
                             llvm::ArrayRef<Value *> offsets,
                             const llvm::Twine &Name = "");

  // Returns the integer type used to represent pointers in traced code.
  llvm::Type *getPointerStorageTy(AddrSpace as);

  // Creates a store with the given alignment.
  StoreInst *createAlignedStore(Value *val, Value *ptr, unsigned align);

private:
  Module &module_;
  BPFtrace &bpftrace_;
  AsyncIds &async_ids_;

  // moves the insertion point to the start of the function you're inside,
  // invokes functor, then moves the insertion point back to its original
  // position. this enables you to emit instructions at the start of your
  // function. you might want to "hoist" an alloca to make it available to
  // blocks that do not follow from yours, for example to make $a accessible in
  // both branches here:
  // BEGIN { if (nsecs > 0) { $a = 1 } else { $a = 2 } print($a); exit() }
  void hoist(const std::function<void()> &functor);

  CallInst *createHelperCall(libbpf::bpf_func_id func_id,
                             FunctionType *helper_type,
                             ArrayRef<Value *> args,
                             const Twine &Name,
                             const Location &loc);

  CallInst *createGetPidTgid(const Location &loc);
  void createGetNsPidTgid(Value *ctx,
                          Value *dev,
                          Value *ino,
                          AllocaInst *ret,
                          const Location &loc);
  llvm::Type *BpfPidnsInfoType();
  Value *createUSDTReadArgument(Value *ctx,
                                struct bcc_usdt_argument *argument,
                                Builtin &builtin,
                                AddrSpace as,
                                const Location &loc);
  CallInst *createMapLookup(const std::string &map_name,
                            Value *key,
                            const std::string &name = "lookup_elem");
  CallInst *createPerCpuMapLookup(
      const std::string &map_name,
      Value *key,
      Value *cpu,
      const std::string &name = "lookup_percpu_elem");
  CallInst *createPerCpuMapLookup(
      const std::string &map_name,
      Value *key,
      Value *cpu,
      PointerType *val_ptr_ty,
      const std::string &name = "lookup_percpu_elem");
  CallInst *createGetScratchMap(const std::string &map_name,
                                const std::string &name,
                                const Location &loc,
                                BasicBlock *failure_callback,
                                int key = 0);
  Value *createReadMapValueAllocation(const SizedType &value_type,
                                      const std::string &name,
                                      const Location &loc);
  Value *createAllocation(globalvars::GlobalVar globalvar,
                          llvm::Type *obj_type,
                          const std::string &name,
                          const Location &loc,
                          std::optional<std::function<size_t(AsyncIds &)>>
                              gen_async_id_cb = std::nullopt);
  void createAllocationInit(const SizedType &stype, Value *alloc);
  Value *createScratchBuffer(globalvars::GlobalVar globalvar,
                             const Location &loc,
                             size_t key);
  libbpf::bpf_func_id selectProbeReadHelper(AddrSpace as, bool str);

  llvm::Type *getKernelPointerStorageTy();
  llvm::Type *getUserPointerStorageTy();
  void createRingbufOutput(Value *data, size_t size, const Location &loc);
  void createPerfEventOutput(Value *ctx,
                             Value *data,
                             size_t size,
                             const Location &loc);

  void createPerCpuSum(AllocaInst *ret, CallInst *call, const SizedType &type);
  void createPerCpuMinMax(AllocaInst *ret,
                          AllocaInst *is_ret_set,
                          CallInst *call,
                          const SizedType &type);
  void createPerCpuAvg(AllocaInst *total,
                       AllocaInst *count,
                       CallInst *call,
                       const SizedType &type);

  std::map<std::string, StructType *> structs_;
  llvm::Function *preserve_static_offset_ = nullptr;
};

} // namespace bpftrace::ast
