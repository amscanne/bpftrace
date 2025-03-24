include(BuildIR)

btf_header(vmlinux
  OUTPUT vmlinux.h
)

llvm_ir(base_ir
  OUTPUT base.ll
  SOURCE base.c
)
