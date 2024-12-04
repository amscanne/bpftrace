#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, preserve_static_offset)
{
  // Standard optimization passes may fold the args.pid into a value that no
  // longer is a dereference by static offset. The `preserve_static_offset`
  // instrinsic should be inserted always in order to ensure that code
  // generated is always compliant. The below ensures that the same value is
  // used enough that LLVM decides to make it an incremental value via CSE,
  // which triggers the error during validation.
  test(R"PROG(
BEGIN {
  @args[1] = (uint64)1;
}
tracepoint:syscalls:sys_enter_kill
{
  if (strcontains(comm, "fb-oomd")) {
    @test[args.pid] = 1;
  }
  if (args.pid == @args[1]) {
    print((1));
  }
  if (args.pid == @args[1]) {
    print((1));
  }
}
)PROG",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
