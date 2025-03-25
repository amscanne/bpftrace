#include <vector>

#include "ast/ast.h"
#include "ast/passes/builtin_functions.h"
#include "functions.h"

namespace bpftrace::ast {

struct FuncProto {
  std::string name;
  SizedType return_type;
  std::vector<Param> params;
};

static registerAll(FunctionRegistry &registry)
{
  static std::vector<FuncProto> builtins = {
    { "count", Type::count_t, {} },
    { "sum", Type::count_t, { Type::integer } },
    { "max", Type::max_t, { Type::integer } },
    { "avg", Type::avg_t, { Type::integer } },
    { "stats", Type::stats_t, { Type::integer } },
    { "hist", Type::hist_t, { Type::integer } },
    { "lhist",
      Type::lhist_t,
      { Type::integer, Type::integer, Type::integer, Type::integer } },
    { "delete" },
    { "has_key" }
  };
  for (const auto &proto : builtins) {
    registry.add(
        Function::Origin::Builtin, proto.name, proto.return_type, proto.params);
  }
}

else if (call.func == "str")
{
  uint64_t max_strlen = bpftrace_.config_->get(ConfigKeyInt::max_strlen);
  // Largest read we'll allow = our global string buffer size
  Value *strlen = b_.getInt64(max_strlen);
  if (call.vargs.size() > 1) {
    auto scoped_arg = visit(call.vargs.at(1));
    Value *proposed_strlen = scoped_arg.value();

    // integer comparison: unsigned less-than-or-equal-to
    CmpInst::Predicate P = CmpInst::ICMP_ULE;
    // check whether proposed_strlen is less-than-or-equal-to maximum
    Value *Cmp = b_.CreateICmp(P, proposed_strlen, strlen, "str.min.cmp");
    // select proposed_strlen if it's sufficiently low, otherwise choose
    // maximum
    strlen = b_.CreateSelect(Cmp, proposed_strlen, strlen, "str.min.select");
  }

  Value *buf = b_.CreateGetStrAllocation("str", call.loc);
  b_.CreateMemsetBPF(buf, b_.getInt8(0), max_strlen);
  auto *arg0 = call.vargs.front();
  auto scoped_expr = visit(call.vargs.front());
  b_.CreateProbeReadStr(
      ctx_, buf, strlen, scoped_expr.value(), arg0->type.GetAS(), call.loc);

  if (dyn_cast<AllocaInst>(buf))
    return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
  return ScopedExpr(buf);
}
else if (call.func == "buf")
{
  const uint64_t max_strlen = bpftrace_.config_->get(ConfigKeyInt::max_strlen);
  // Subtract out metadata headroom
  uint64_t fixed_buffer_length = max_strlen - sizeof(AsyncEvent::Buf);
  Value *max_length = b_.getInt64(fixed_buffer_length);
  Value *length;

  if (call.vargs.size() > 1) {
    auto &arg = *call.vargs.at(1);
    auto scoped_expr = visit(&arg);

    Value *proposed_length = scoped_expr.value();
    if (arg.type.GetSize() != 8)
      proposed_length = b_.CreateZExt(proposed_length, max_length->getType());
    Value *cmp = b_.CreateICmp(
        CmpInst::ICMP_ULE, proposed_length, max_length, "length.cmp");
    length = b_.CreateSelect(cmp, proposed_length, max_length, "length.select");

    auto literal_length = bpftrace_.get_int_literal(&arg);
    if (literal_length)
      fixed_buffer_length = *literal_length;
  } else {
    auto &arg = *call.vargs.at(0);
    fixed_buffer_length = arg.type.GetNumElements() *
                          arg.type.GetElementTy()->GetSize();
    length = b_.getInt32(fixed_buffer_length);
  }

  Value *buf = b_.CreateGetStrAllocation("buf", call.loc);
  auto elements = AsyncEvent::Buf().asLLVMType(b_, fixed_buffer_length);
  std::ostringstream dynamic_sized_struct_name;
  dynamic_sized_struct_name << "buffer_" << fixed_buffer_length << "_t";
  StructType *buf_struct = b_.GetStructType(dynamic_sized_struct_name.str(),
                                            elements,
                                            true);

  Value *buf_len_offset = b_.CreateGEP(buf_struct,
                                       buf,
                                       { b_.getInt32(0), b_.getInt32(0) });
  length = b_.CreateIntCast(length, buf_struct->getElementType(0), false);
  b_.CreateStore(length, buf_len_offset);

  Value *buf_data_offset = b_.CreateGEP(buf_struct,
                                        buf,
                                        { b_.getInt32(0), b_.getInt32(1) });
  b_.CreateMemsetBPF(buf_data_offset, b_.getInt8(0), fixed_buffer_length);

  auto scoped_expr = visit(call.vargs.front());
  auto *arg0 = call.vargs.front();
  b_.CreateProbeRead(ctx_,
                     buf_data_offset,
                     length,
                     scoped_expr.value(),
                     find_addrspace_stack(arg0->type),
                     call.loc);

  if (dyn_cast<AllocaInst>(buf))
    return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
  return ScopedExpr(buf);
}
else if (call.func == "path")
{
  Value *buf = b_.CreateGetStrAllocation("path", call.loc);
  b_.CreateMemsetBPF(buf,
                     b_.getInt8(0),
                     bpftrace_.config_->get(ConfigKeyInt::max_strlen));
  const uint64_t max_size = bpftrace_.config_->get(ConfigKeyInt::max_strlen);
  Value *sz;
  if (call.vargs.size() > 1) {
    auto scoped_arg = visit(call.vargs.at(1));
    Value *pr_sz = b_.CreateIntCast(scoped_arg.value(), b_.getInt32Ty(), false);
    Value *max_sz = b_.getInt32(max_size);
    Value *cmp = b_.CreateICmp(
        CmpInst::ICMP_ULE, pr_sz, max_sz, "path.size.cmp");
    sz = b_.CreateSelect(cmp, pr_sz, max_sz, "path.size.select");
  } else {
    sz = b_.getInt32(max_size);
  }

  auto scoped_arg = visit(*call.vargs.front());
  Value *value = scoped_arg.value();
  b_.CreatePath(ctx_,
                buf,
                b_.CreateCast(value->getType()->isPointerTy()
                                  ? Instruction::BitCast
                                  : Instruction::IntToPtr,
                              value,
                              b_.getPtrTy()),
                sz,
                call.loc);

  if (dyn_cast<AllocaInst>(buf))
    return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
  return ScopedExpr(buf);
}
else if (call.func == "kaddr")
{
  uint64_t addr;
  auto name = bpftrace_.get_string_literal(call.vargs.at(0));
  addr = bpftrace_.resolve_kname(name);
  if (!addr)
    call.addError() << "Failed to resolve kernel symbol: " << name;
  return ScopedExpr(b_.getInt64(addr));
}
else if (call.func == "percpu_kaddr")
{
  auto name = bpftrace_.get_string_literal(call.vargs.at(0));
  auto *var = DeclareKernelVar(name);
  Value *percpu_ptr;
  if (call.vargs.size() == 1) {
    percpu_ptr = b_.CreateThisCpuPtr(var, call.loc);
  } else {
    auto scoped_cpu = visit(call.vargs.at(1));
    percpu_ptr = b_.CreatePerCpuPtr(var, scoped_cpu.value(), call.loc);
  }
  return ScopedExpr(b_.CreatePtrToInt(percpu_ptr, b_.getInt64Ty()));
}
else if (call.func == "uaddr")
{
  auto name = bpftrace_.get_string_literal(call.vargs.at(0));
  struct symbol sym = {};
  int err = bpftrace_.resolve_uname(name, &sym, current_attach_point_->target);
  if (err < 0 || sym.address == 0)
    call.addError() << "Could not resolve symbol: "
                    << current_attach_point_->target << ":" << name;
  return ScopedExpr(b_.getInt64(sym.address));
}
else if (call.func == "cgroupid")
{
  uint64_t cgroupid;
  auto path = bpftrace_.get_string_literal(call.vargs.at(0));
  cgroupid = util::resolve_cgroupid(path);
  return ScopedExpr(b_.getInt64(cgroupid));
}
else if (call.func == "join")
{
  auto *arg0 = call.vargs.front();
  auto scoped_arg = visit(arg0);
  auto addrspace = arg0->type.GetAS();

  llvm::Function *parent = b_.GetInsertBlock()->getParent();
  BasicBlock *failure_callback = BasicBlock::Create(module_->getContext(),
                                                    "failure_callback",
                                                    parent);
  Value *perfdata = b_.CreateGetJoinMap(failure_callback, call.loc);

  // arg0
  b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::join)), perfdata);
  b_.CreateStore(b_.getInt64(async_ids_.join()),
                 b_.CreateGEP(b_.getInt8Ty(), perfdata, b_.getInt64(8)));

  SizedType elem_type = CreatePointer(CreateInt8(), addrspace);
  size_t ptr_width = b_.getPointerStorageTy(addrspace)->getIntegerBitWidth();
  assert(b_.GetType(elem_type) == b_.getInt64Ty());

  // temporary that stores the value of arg[i]
  Value *value = scoped_arg.value();
  AllocaInst *arr = b_.CreateAllocaBPF(b_.getInt64Ty(), call.func + "_r0");
  b_.CreateProbeRead(ctx_, arr, elem_type, value, call.loc);
  b_.CreateProbeReadStr(
      ctx_,
      b_.CreateGEP(b_.getInt8Ty(), perfdata, b_.getInt64(8 + 8)),
      bpftrace_.join_argsize_,
      b_.CreateLoad(b_.getInt64Ty(), arr),
      addrspace,
      call.loc);

  for (unsigned int i = 1; i < bpftrace_.join_argnum_; i++) {
    // advance to the next array element
    value = b_.CreateAdd(value, b_.getInt64(ptr_width / 8));

    b_.CreateProbeRead(ctx_, arr, elem_type, value, call.loc);
    b_.CreateProbeReadStr(
        ctx_,
        b_.CreateGEP(b_.getInt8Ty(),
                     perfdata,
                     b_.getInt64(8 + 8 + (i * bpftrace_.join_argsize_))),
        bpftrace_.join_argsize_,
        b_.CreateLoad(b_.getInt64Ty(), arr),
        addrspace,
        call.loc);
  }

  // emit
  b_.CreateOutput(ctx_,
                  perfdata,
                  8 + 8 + (bpftrace_.join_argnum_ * bpftrace_.join_argsize_),
                  call.loc);

  b_.CreateBr(failure_callback);

  // if we cannot find a valid map value, we will output nothing and continue
  b_.SetInsertPoint(failure_callback);
  return ScopedExpr();
}
else if (call.func == "ksym")
{
  // We want to just pass through from the child node.
  return visit(call.vargs.front());
}
else if (call.func == "usym")
{
  auto scoped_arg = visit(call.vargs.front());
  return ScopedExpr(
      b_.CreateUSym(ctx_, scoped_arg.value(), get_probe_id(), call.loc),
      std::move(scoped_arg));
}
else if (call.func == "ntop")
{
  // struct {
  //   int af_type;
  //   union {
  //     char[4] inet4;
  //     char[16] inet6;
  //   }
  // }
  //}
  std::vector<llvm::Type *> elements = { b_.getInt64Ty(),
                                         ArrayType::get(b_.getInt8Ty(), 16) };
  StructType *inet_struct = b_.GetStructType("inet", elements, false);

  AllocaInst *buf = b_.CreateAllocaBPF(inet_struct, "inet");

  Value *af_offset = b_.CreateGEP(inet_struct,
                                  buf,
                                  { b_.getInt64(0), b_.getInt32(0) });
  Value *af_type;

  auto *inet = call.vargs.at(0);
  if (call.vargs.size() == 1) {
    if (inet->type.IsIntegerTy() || inet->type.GetSize() == 4) {
      af_type = b_.getInt64(AF_INET);
    } else {
      af_type = b_.getInt64(AF_INET6);
    }
  } else {
    inet = call.vargs.at(1);
    auto scoped_arg = visit(call.vargs.at(0));
    af_type = b_.CreateIntCast(scoped_arg.value(), b_.getInt64Ty(), true);
  }
  b_.CreateStore(af_type, af_offset);

  Value *inet_offset = b_.CreateGEP(inet_struct,
                                    buf,
                                    { b_.getInt32(0), b_.getInt32(1) });
  b_.CreateMemsetBPF(inet_offset, b_.getInt8(0), 16);

  auto scoped_inet = visit(inet);
  if (inet->type.IsArrayTy() || inet->type.IsStringTy()) {
    b_.CreateProbeRead(ctx_,
                       static_cast<AllocaInst *>(inet_offset),
                       inet->type,
                       scoped_inet.value(),
                       call.loc);
  } else {
    b_.CreateStore(
        b_.CreateIntCast(scoped_inet.value(), b_.getInt32Ty(), false),
        inet_offset);
  }

  return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
}
else if (call.func == "pton")
{
  auto af_type = AF_INET;
  int addr_size = 4;
  std::string addr = bpftrace_.get_string_literal(call.vargs.at(0));
  if (addr.find(":") != std::string::npos) {
    af_type = AF_INET6;
    addr_size = 16;
  }

  llvm::Type *array_t = ArrayType::get(b_.getInt8Ty(), addr_size);
  AllocaInst *buf;
  if (af_type == AF_INET6) {
    buf = b_.CreateAllocaBPF(array_t, "addr6");
  } else {
    buf = b_.CreateAllocaBPF(array_t, "addr4");
  }

  std::vector<char> dst(addr_size);
  Value *octet;
  auto ret = inet_pton(af_type, addr.c_str(), dst.data());
  if (ret != 1) {
    call.addError() << "inet_pton() call returns " << std::to_string(ret);
  }
  for (int i = 0; i < addr_size; i++) {
    octet = b_.getInt8(dst[i]);
    b_.CreateStore(
        octet, b_.CreateGEP(array_t, buf, { b_.getInt64(0), b_.getInt64(i) }));
  }

  return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
}
else if (call.func == "reg")
{
  auto reg_name = bpftrace_.get_string_literal(call.vargs.at(0));
  int offset = arch::offset(reg_name);
  if (offset == -1) {
    call.addError() << "negative offset on reg() call";
  }

  return ScopedExpr(
      b_.CreateRegisterRead(ctx_, offset, call.func + "_" + reg_name));
}
else if (call.func == "printf")
{
  // We overload printf call for iterator probe's seq_printf helper.
  if (!inside_subprog_ &&
      probetype(current_attach_point_->provider) == ProbeType::iter) {
    auto nargs = call.vargs.size() - 1;

    int ptr_size = sizeof(unsigned long);
    int data_size = 0;

    // create buffer to store the argument expression values
    SizedType data_type = CreateArray(nargs, CreateUInt64());
    AllocaInst *data = b_.CreateAllocaBPFInit(data_type, "data");

    std::vector<ScopedExpr> scoped_args;
    scoped_args.reserve(call.vargs.size());
    for (size_t i = 1; i < call.vargs.size(); i++) {
      // process argument expression
      Expression &arg = *call.vargs.at(i);
      auto scoped_arg = visit(&arg);
      Value *value = scoped_arg.value();

      // and store it to data area
      Value *offset = b_.CreateGEP(b_.GetType(data_type),
                                   data,
                                   { b_.getInt64(0), b_.getInt32(i - 1) });
      b_.CreateStore(value, offset);

      // keep the expression alive, so it's still there
      // for following seq_printf call
      scoped_args.emplace_back(std::move(scoped_arg));
      data_size += ptr_size;
    }

    // pick the current format string
    auto print_id = async_ids_.bpf_print();
    auto *fmt = createFmtString(print_id);
    auto size = bpftrace_.resources.bpf_print_fmts.at(print_id).size() + 1;

    // and finally the seq_printf call
    b_.CreateSeqPrintf(ctx_,
                       b_.CreateIntToPtr(fmt, b_.getPtrTy()),
                       b_.getInt32(size),
                       data,
                       b_.getInt32(data_size),
                       call.loc);
    return ScopedExpr();

  } else {
    createFormatStringCall(call,
                           async_ids_.printf(),
                           bpftrace_.resources.printf_args,
                           "printf",
                           AsyncAction::printf);
    return ScopedExpr();
  }
}
else if (call.func == "debugf")
{
  auto print_id = async_ids_.bpf_print();
  auto *fmt = createFmtString(print_id);
  auto size = bpftrace_.resources.bpf_print_fmts.at(print_id).size() + 1;

  std::vector<Value *> values;
  std::vector<ScopedExpr> exprs;
  for (size_t i = 1; i < call.vargs.size(); i++) {
    Expression &arg = *call.vargs.at(i);
    auto scoped_expr = visit(arg);
    values.push_back(scoped_expr.value());
    exprs.emplace_back(std::move(scoped_expr));
  }

  b_.CreateTracePrintk(b_.CreateIntToPtr(fmt, b_.getPtrTy()),
                       b_.getInt32(size),
                       values,
                       call.loc);
  return ScopedExpr();
}
else if (call.func == "system")
{
  createFormatStringCall(call,
                         async_ids_.system(),
                         bpftrace_.resources.system_args,
                         "system",
                         AsyncAction::syscall);
  return ScopedExpr();
}
else if (call.func == "cat")
{
  createFormatStringCall(call,
                         async_ids_.cat(),
                         bpftrace_.resources.cat_args,
                         "cat",
                         AsyncAction::cat);
  return ScopedExpr();
}
else if (call.func == "exit")
{
  auto elements = AsyncEvent::Exit().asLLVMType(b_);
  StructType *exit_struct = b_.GetStructType("exit_t", elements, true);
  AllocaInst *buf = b_.CreateAllocaBPF(exit_struct, "exit");
  size_t struct_size = datalayout().getTypeAllocSize(exit_struct);

  // Fill in exit struct.
  b_.CreateStore(
      b_.getInt64(asyncactionint(AsyncAction::exit)),
      b_.CreateGEP(exit_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));

  Value *code = b_.getInt8(0);
  if (call.vargs.size() == 1) {
    auto scoped_expr = visit(call.vargs.at(0));
    code = scoped_expr.value();
  }
  b_.CreateStore(
      code, b_.CreateGEP(exit_struct, buf, { b_.getInt64(0), b_.getInt32(1) }));

  b_.CreateOutput(ctx_, buf, struct_size, call.loc);
  b_.CreateLifetimeEnd(buf);

  createRet();

  // create an unreachable basic block for all the "dead instructions" that
  // may come after exit(). If we don't, LLVM will emit the instructions
  // leading to a `unreachable insn` warning from the verifier
  BasicBlock *deadcode = BasicBlock::Create(module_->getContext(),
                                            "deadcode",
                                            b_.GetInsertBlock()->getParent());
  b_.SetInsertPoint(deadcode);
  return ScopedExpr();
}
else if (call.func == "print")
{
  auto &arg = *call.vargs.at(0);
  if (arg.is_map) {
    auto &map = static_cast<Map &>(arg);
    if (map.key_expr)
      createPrintNonMapCall(call, async_ids_.non_map_print());
    else
      createPrintMapCall(call);
  } else {
    createPrintNonMapCall(call, async_ids_.non_map_print());
  }
  return ScopedExpr();
}
else if (call.func == "cgroup_path")
{
  auto elements = AsyncEvent::CgroupPath().asLLVMType(b_);
  StructType *cgroup_path_struct = b_.GetStructType(call.func + "_t",
                                                    elements,
                                                    true);
  AllocaInst *buf = b_.CreateAllocaBPF(cgroup_path_struct, call.func + "_args");

  // Store cgroup path event id
  b_.CreateStore(b_.GetIntSameSize(async_ids_.cgroup_path(), elements.at(0)),
                 b_.CreateGEP(cgroup_path_struct,
                              buf,
                              { b_.getInt64(0), b_.getInt32(0) }));

  // Store cgroup id
  auto *arg = call.vargs.at(0);
  auto scoped_expr = visit(arg);
  b_.CreateStore(scoped_expr.value(),
                 b_.CreateGEP(cgroup_path_struct,
                              buf,
                              { b_.getInt64(0), b_.getInt32(1) }));

  return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
}
else if (call.func == "clear" || call.func == "zero")
{
  auto elements = AsyncEvent::MapEvent().asLLVMType(b_);
  StructType *event_struct = b_.GetStructType(call.func + "_t", elements, true);

  auto &arg = *call.vargs.at(0);
  auto &map = static_cast<Map &>(arg);

  AllocaInst *buf = b_.CreateAllocaBPF(event_struct,
                                       call.func + "_" + map.ident);

  auto *aa_ptr = b_.CreateGEP(event_struct,
                              buf,
                              { b_.getInt64(0), b_.getInt32(0) });
  if (call.func == "clear")
    b_.CreateStore(b_.GetIntSameSize(asyncactionint(AsyncAction::clear),
                                     elements.at(0)),
                   aa_ptr);
  else
    b_.CreateStore(b_.GetIntSameSize(asyncactionint(AsyncAction::zero),
                                     elements.at(0)),
                   aa_ptr);

  int id = bpftrace_.resources.maps_info.at(map.ident).id;
  if (id == -1) {
    LOG(BUG) << "map id for map \"" << map.ident << "\" not found";
  }
  auto *ident_ptr = b_.CreateGEP(event_struct,
                                 buf,
                                 { b_.getInt64(0), b_.getInt32(1) });
  b_.CreateStore(b_.GetIntSameSize(id, elements.at(1)), ident_ptr);

  b_.CreateOutput(ctx_, buf, getStructSize(event_struct), call.loc);
  return ScopedExpr(buf, [this, buf] { b_.CreateLifetimeEnd(buf); });
}
else if (call.func == "len")
{
  if (call.vargs.at(0)->type.IsStack()) {
    auto *arg = call.vargs.at(0);
    auto scoped_arg = visit(arg);

    auto *stack_key_struct = b_.GetStackStructType(arg->type.IsUstackTy());
    Value *nr_stack_frames = b_.CreateGEP(stack_key_struct,
                                          scoped_arg.value(),
                                          { b_.getInt64(0), b_.getInt32(1) });
    return ScopedExpr(
        b_.CreateIntCast(b_.CreateLoad(b_.getInt64Ty(), nr_stack_frames),
                         b_.getInt64Ty(),
                         false));
  } else /* call.vargs.at(0)->is_map */ {
    auto &arg = *call.vargs.at(0);
    auto &map = static_cast<Map &>(arg);

    // Some map types used in bpftrace (BPF_MAP_TYPE_(PERCPU_)ARRAY) do not
    // implement per-cpu counters and bpf_map_sum_elem_count would always
    // return 0 for them. In our case, those maps typically have a single
    // element so we can return 1 straight away.
    // For the rest, use bpf_map_sum_elem_count if available and map supports
    // it, otherwise fall back to bpf_for_each_map_elem with a custom callback
    if (map_has_single_elem(map.type, map.key_type)) {
      return ScopedExpr(b_.getInt64(1));
    } else if (bpftrace_.feature_->has_kernel_func(
                   Kfunc::bpf_map_sum_elem_count) &&
               !is_array_map(map.type, map.key_type)) {
      return ScopedExpr(CreateKernelFuncCall(Kfunc::bpf_map_sum_elem_count,
                                             { b_.GetMapVar(map.ident) },
                                             "len",
                                             call));
    } else {
      if (!map_len_func_)
        map_len_func_ = createMapLenCallback();

      return ScopedExpr(
          b_.CreateForEachMapElem(ctx_, map, map_len_func_, nullptr, call.loc));
    }
  }
}
else if (call.func == "time")
{
  auto elements = AsyncEvent::Time().asLLVMType(b_);
  StructType *time_struct = b_.GetStructType(call.func + "_t", elements, true);

  AllocaInst *buf = b_.CreateAllocaBPF(time_struct, call.func + "_t");

  b_.CreateStore(
      b_.GetIntSameSize(asyncactionint(AsyncAction::time), elements.at(0)),
      b_.CreateGEP(time_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));

  b_.CreateStore(
      b_.GetIntSameSize(async_ids_.time(), elements.at(1)),
      b_.CreateGEP(time_struct, buf, { b_.getInt64(0), b_.getInt32(1) }));

  b_.CreateOutput(ctx_, buf, getStructSize(time_struct), call.loc);
  return ScopedExpr(buf, [this, buf] { b_.CreateLifetimeEnd(buf); });
}
else if (call.func == "strftime")
{
  auto elements = AsyncEvent::Strftime().asLLVMType(b_);
  StructType *strftime_struct = b_.GetStructType(call.func + "_t",
                                                 elements,
                                                 true);

  AllocaInst *buf = b_.CreateAllocaBPF(strftime_struct, call.func + "_args");
  b_.CreateStore(
      b_.GetIntSameSize(async_ids_.strftime(), elements.at(0)),
      b_.CreateGEP(strftime_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));
  b_.CreateStore(
      b_.GetIntSameSize(static_cast<std::underlying_type_t<TimestampMode>>(
                            call.type.ts_mode),
                        elements.at(1)),
      b_.CreateGEP(strftime_struct, buf, { b_.getInt64(0), b_.getInt32(1) }));
  auto &arg = *call.vargs.at(1);
  auto scoped_expr = visit(arg);
  b_.CreateStore(
      scoped_expr.value(),
      b_.CreateGEP(strftime_struct, buf, { b_.getInt64(0), b_.getInt32(2) }));
  return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
}
else if (call.func == "kstack" || call.func == "ustack")
{
  return kstack_ustack(call.func, call.type.stack_type, call.loc);
}
else if (call.func == "signal")
{
  // long bpf_send_signal(u32 sig)
  auto &arg = *call.vargs.at(0);
  if (arg.type.IsStringTy()) {
    auto signame = bpftrace_.get_string_literal(&arg);
    int sigid = signal_name_to_num(signame);
    // Should be caught in semantic analyser
    if (sigid < 1) {
      LOG(BUG) << "Invalid signal ID for \"" << signame << "\"";
    }
    b_.CreateSignal(ctx_, b_.getInt32(sigid), call.loc);
    return ScopedExpr();
  }
  auto scoped_arg = visit(arg);
  Value *sig_number = b_.CreateIntCast(scoped_arg.value(),
                                       b_.getInt32Ty(),
                                       arg.type.IsSigned());
  b_.CreateSignal(ctx_, sig_number, call.loc);
  return ScopedExpr();
}
else if (call.func == "strerror")
{
  return visit(call.vargs.front());
}
else if (call.func == "strncmp")
{
  auto &left_arg = *call.vargs.at(0);
  auto &right_arg = *call.vargs.at(1);
  auto size_opt = bpftrace_.get_int_literal(call.vargs.at(2));
  if (!size_opt.has_value())
    LOG(BUG) << "Int literal should have been checked in semantic analysis";
  uint64_t size = std::min({ static_cast<uint64_t>(*size_opt),
                             left_arg.type.GetSize(),
                             right_arg.type.GetSize() });

  auto left_string = visit(&left_arg);
  auto right_string = visit(&right_arg);

  return ScopedExpr(
      b_.CreateStrncmp(left_string.value(), right_string.value(), size, false));
}
else if (call.func == "strcontains")
{
  auto &left_arg = *call.vargs.at(0);
  auto &right_arg = *call.vargs.at(1);

  auto left_string = visit(left_arg);
  auto right_string = visit(right_arg);

  return ScopedExpr(b_.CreateStrcontains(left_string.value(),
                                         left_arg.type.GetSize(),
                                         right_string.value(),
                                         right_arg.type.GetSize()));
}
else if (call.func == "override")
{
  // long bpf_override(struct pt_regs *regs, u64 rc)
  // returns: 0
  auto &arg = *call.vargs.at(0);
  auto scoped_arg = visit(arg);
  auto *expr = b_.CreateIntCast(scoped_arg.value(),
                                b_.getInt64Ty(),
                                arg.type.IsSigned());
  b_.CreateOverrideReturn(ctx_, expr);
  return ScopedExpr();
}
else if (call.func == "kptr" || call.func == "uptr")
{
  return visit(call.vargs.at(0));
}
else if (call.func == "macaddr")
{
  // MAC addresses are presented as char[6]
  AllocaInst *buf = b_.CreateAllocaBPFInit(call.type, "macaddr");
  auto *macaddr = call.vargs.front();
  auto scoped_arg = visit(macaddr);

  if (inBpfMemory(macaddr->type))
    b_.CreateMemcpyBPF(buf, scoped_arg.value(), macaddr->type.GetSize());
  else
    b_.CreateProbeRead(ctx_, buf, macaddr->type, scoped_arg.value(), call.loc);

  return ScopedExpr(buf, [this, buf]() { b_.CreateLifetimeEnd(buf); });
}
else if (call.func == "unwatch")
{
  auto scoped_addr = visit(call.vargs.at(0));

  auto elements = AsyncEvent::WatchpointUnwatch().asLLVMType(b_);
  StructType *unwatch_struct = b_.GetStructType("unwatch_t", elements, true);
  AllocaInst *buf = b_.CreateAllocaBPF(unwatch_struct, "unwatch");
  size_t struct_size = datalayout().getTypeAllocSize(unwatch_struct);

  b_.CreateStore(
      b_.getInt64(asyncactionint(AsyncAction::watchpoint_detach)),
      b_.CreateGEP(unwatch_struct, buf, { b_.getInt64(0), b_.getInt32(0) }));
  b_.CreateStore(
      b_.CreateIntCast(scoped_addr.value(),
                       b_.getInt64Ty(),
                       false /* unsigned */),
      b_.CreateGEP(unwatch_struct, buf, { b_.getInt64(0), b_.getInt32(1) }));
  b_.CreateOutput(ctx_, buf, struct_size, call.loc);
  return ScopedExpr(buf, [this, buf] { b_.CreateLifetimeEnd(buf); });
}
else if (call.func == "bswap")
{
  bpftrace::ast::Expression *arg = call.vargs.at(0);
  auto scoped_arg = visit(call.vargs.at(0));

  assert(arg->type.IsIntegerTy());
  if (arg->type.GetSize() > 1) {
    llvm::Type *arg_type = b_.GetType(arg->type);
#if LLVM_VERSION_MAJOR >= 20
    llvm::Function *swap_fun = Intrinsic::getOrInsertDeclaration(
        module_.get(), Intrinsic::bswap, { arg_type });
#else
    llvm::Function *swap_fun = Intrinsic::getDeclaration(module_.get(),
                                                         Intrinsic::bswap,
                                                         { arg_type });
#endif

    return ScopedExpr(b_.CreateCall(swap_fun, { scoped_arg.value() }),
                      std::move(scoped_arg));
  }
  return scoped_arg;
}
else if (call.func == "skboutput")
{
  auto elements = AsyncEvent::SkbOutput().asLLVMType(b_);
  StructType *hdr_t = b_.GetStructType("hdr_t", elements, false);
  AllocaInst *data = b_.CreateAllocaBPF(hdr_t, "hdr");

  // The extra 0 here ensures the type of addr_offset will be int64
  Value *aid_addr = b_.CreateGEP(hdr_t,
                                 data,
                                 { b_.getInt64(0), b_.getInt32(0) });
  Value *id_addr = b_.CreateGEP(hdr_t,
                                data,
                                { b_.getInt64(0), b_.getInt32(1) });
  Value *time_addr = b_.CreateGEP(hdr_t,
                                  data,
                                  { b_.getInt64(0), b_.getInt32(2) });

  b_.CreateStore(b_.getInt64(asyncactionint(AsyncAction::skboutput)), aid_addr);
  b_.CreateStore(b_.getInt64(async_ids_.skb_output()), id_addr);
  b_.CreateStore(b_.CreateGetNs(TimestampMode::boot, call.loc), time_addr);

  auto scoped_skb = visit(call.vargs.at(1));
  auto scoped_arg_len = visit(call.vargs.at(2));
  Value *len = b_.CreateIntCast(scoped_arg_len.value(), b_.getInt64Ty(), false);
  Value *ret = b_.CreateSkbOutput(
      scoped_skb.value(), len, data, getStructSize(hdr_t));
  return ScopedExpr(ret);
}
else if (call.func == "nsecs")
{
  if (call.type.ts_mode == TimestampMode::sw_tai) {
    if (!bpftrace_.delta_taitime_.has_value())
      LOG(BUG) << "Should have been checked in semantic analysis";
    uint64_t delta = (bpftrace_.delta_taitime_->tv_sec * 1e9) +
                     bpftrace_.delta_taitime_->tv_nsec;
    Value *ns = b_.CreateGetNs(TimestampMode::boot, call.loc);
    return ScopedExpr(b_.CreateAdd(ns, b_.getInt64(delta)));
  } else {
    return ScopedExpr(b_.CreateGetNs(call.type.ts_mode, call.loc));
  }
}
else
{
  LOG(BUG) << "missing codegen for function \"" << call.func << "\"";
  __builtin_unreachable();
}

static std::vector<DeprecatedName> DEPRECATED_BUILTINS = {
  {
      .old_name = "sarg*",
      .new_name = "*(reg(\"sp\") + <stack_offset>)",
      .deleted = false,
  },
};

void DeprecatedAnalyser::visit(Builtin &builtin)
{
  check(DEPRECATED_BUILTINS, builtin.ident, builtin);
}

static std::vector<DeprecatedName> DEPRECATED_CALLS = {};

void DeprecatedAnalyser::visit(Call &call)
{
  check(DEPRECATED_CALLS, call.func, call);
}

static std::vector<DeprecatedName> DEPRECATED_CONFIGS = {
  {
      .old_name = "symbol_source",
      .new_name = {},
      .deleted = true,
  },
};

void DeprecatedAnalyser::visit(AssignConfigVarStatement &assign)
{
  check(DEPRECATED_CONFIGS, assign.config_var, assign);
}

Pass CreateDeprecatedPass()
{
  auto fn = [](ASTContext &ast) {
    DeprecatedAnalyser deprecated;
    deprecated.visit(ast.root);
  };

  return Pass::create("Deprecated", fn);
}

} // namespace bpftrace::ast
