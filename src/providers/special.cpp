#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <linux/bpf.h>

#include "bpfprogram.h"
#include "log.h"
#include "providers/special.h"
#include "util/result.h"
#include "util/strings.h"

namespace bpftrace::providers {

class SpecialAttachPoint : public AttachPoint {
public:
  SpecialAttachPoint(const Provider &provider,
                     const std::string &name,
                     Action action)
      : AttachPoint(provider, name), action_(action) {};

  bpf_prog_type prog_type() const override
  {
    return BPF_PROG_TYPE_XDP;
  }

  Action action() const override
  {
    return action_;
  }

private:
  Action action_;
};

Result<AttachPointList> SpecialProvider::parse(
    const std::string &str,
    [[maybe_unused]] const BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  return make_list<SpecialAttachPoint>(str, action_);
}

Result<AttachPointList> SelfProvider::parse(
    const std::string &str,
    [[maybe_unused]] const BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  return SpecialProvider::parse(str, btf, pid);
}

Result<> SpecialProvider::run_single(
    [[maybe_unused]] std::unique_ptr<AttachPoint> &attach_point,
    const BpfProgram &prog) const
{
  // See BenchmarkProvider::run_single.
  constexpr size_t ETH_HLEN = 14;
  char data_in[ETH_HLEN];
  struct ::bpf_test_run_opts opts = {};
  opts.data_in = data_in;
  opts.data_size_in = ETH_HLEN;
  opts.repeat = 1;

  if (bpf_prog_test_run_opts(prog.fd(), &opts) < 0) {
    return make_error<SystemError>("failed to run program");
  }

  return OK();
}

} // namespace bpftrace::providers
