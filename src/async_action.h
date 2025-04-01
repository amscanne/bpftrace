#pragma once

#include <cstddef>

namespace bpftrace {

class BPFtrace;

enum class AsyncAction {
  // clang-format off
  printf      = 0,     // printf reserves 0-9999 for printf_ids
  printf_end  = 9999,
  syscall     = 10000, // system reserves 10000-19999 for printf_ids
  syscall_end = 19999,
  cat         = 20000, // cat reserves 20000-29999 for printf_ids
  cat_end     = 29999,
  exit        = 30000,
  print,
  clear,
  zero,
  time,
  join,
  helper_error,
  print_non_map,
  strftime,
  watchpoint_attach,
  watchpoint_detach,
  skboutput,
  // clang-format on
};

namespace async_action {

const static size_t MAX_TIME_STR_LEN = 64;
void join_handler(BPFtrace *bpftrace, void *data);
void time_handler(BPFtrace *bpftrace, void *data);

} // namespace async_action

} // namespace bpftrace
