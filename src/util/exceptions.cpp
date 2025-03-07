#include "util/exceptions.h"

namespace bpftrace::util {

MountNSException::MountNSException(const std::string &msg) : msg_(msg)
{
}

const char *MountNSException::what() const noexcept
{
  return msg_.c_str();
}

} // namespace bpftrace::util
