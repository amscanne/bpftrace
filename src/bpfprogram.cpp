#include <bpf/bpf.h>
#include <elf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "bpfprogram.h"

namespace bpftrace {

BpfProgram::BpfProgram(struct bpf_program *bpf_prog) : bpf_prog_(bpf_prog)
{
}

int BpfProgram::fd() const
{
  return bpf_program__fd(bpf_prog_);
}

void BpfProgram::set_prog_type(bpf_prog_type prog_type)
{
  bpf_program__set_type(bpf_prog_, prog_type);
}

void BpfProgram::set_attach_type(bpf_attach_type attach_type)
{
  bpf_program__set_expected_attach_type(bpf_prog_, attach_type);
}

void BpfProgram::set_attach_target(const std::string &target,
                                   std::optional<util::FD> &&fd)
{
  if (fd) {
    bpf_prog_fd_.emplace(std::move(*fd));
  }
  bpf_program__set_attach_target(bpf_prog_,
                                 bpf_prog_fd_ ? *bpf_prog_fd_ : 0,
                                 target.c_str());
}

void BpfProgram::set_autoload(bool autoload)
{
  bpf_program__set_autoload(bpf_prog_, autoload);
}

void BpfProgram::set_autoattach(bool autoattach)
{
  bpf_program__set_autoattach(bpf_prog_, autoattach);
}

struct bpf_program *BpfProgram::bpf_prog() const
{
  return bpf_prog_;
}

} // namespace bpftrace
