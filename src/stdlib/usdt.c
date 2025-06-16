#include <usdt.bpf.h>

long __usdt_arg(void *ctx, long arg_num)
{
  long _x;
  bpf_usdt_arg(ctx, arg_num, &_x);
  return _x;
}
