#define __TARGET_ARCH_arm64

#include <vmlinux.h>
#include <bpf/usdt.bpf.h>

long __usdt_arg(long ctx, long arg_num)
{
  long _x;
  bpf_usdt_arg((void*)ctx, arg_num, &_x);
  return _x;
}
