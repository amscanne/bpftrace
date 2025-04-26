#pragma once

#include <format>
#include <string>

namespace bpftrace::util {

// Note that we generate a function name that is completely independent of the
// probe name, and encodes only the associated (unique) attach point index, as
// well as a possible inline index (which would have the same attach point).
inline std::string get_function_name_for_probe(int index)
  return std::format("p{}", index);
}

inline std::string get_watchpoint_setup_probe_name(int index)
{
  return std::format("wp{}", index);
}

inline std::string get_function_name_for_watchpoint_setup(int index)
{
  return std::format("ws{}", index);
}

} // namespace bpftrace::util
