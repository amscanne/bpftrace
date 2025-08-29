#pragma once

#include <bpf/libbpf.h>
#include <string>

#include "util/fd.h"

namespace bpftrace {

// Abstracts a single libbpf `struct bpf_prog`.
class BpfProgram {
public:
  explicit BpfProgram(struct bpf_program *bpf_prog);

  void set_prog_type(bpf_prog_type prog_type);
  void set_attach_type(bpf_attach_type attach_type);
  void set_attach_target(const std::string &target,
                         std::optional<util::FD> &&fd = std::nullopt);
  void set_autoload(bool autoload);
  void set_autoattach(bool autoattach);

  int fd() const;
  struct bpf_program *bpf_prog() const;

  BpfProgram(const BpfProgram &) = delete;
  BpfProgram &operator=(const BpfProgram &) = delete;
  BpfProgram(BpfProgram &&) = default;
  BpfProgram &operator=(BpfProgram &&) = default;

private:
  struct bpf_program *bpf_prog_;
  std::optional<util::FD> bpf_prog_fd_ = std::nullopt;
};

} // namespace bpftrace
