#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_path)
{
  test("fentry:filp_close { path(args->filp->f_path); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
