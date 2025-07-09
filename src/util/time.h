#pragma once

#include <chrono>
#include <iostream>

namespace bpftrace::util {

// DisplayUnit is a time display unit.
enum class DisplayUnit {
  ns,
  ms,
  us,
  s,
};

std::ostream &operator<<(std::ostream &out, const DisplayUnit &unit);

// Returns a human-readable unit and the scale-factor for a duration.
std::pair<DisplayUnit, uint64_t> duration_str(
    const std::chrono::duration<uint64_t, std::nano> &ns);

} // namespace bpftrace::util
