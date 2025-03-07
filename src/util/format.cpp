#include "util/format.h"

namespace bpftrace::util {

std::string str_join(const std::vector<std::string> &list,
                     const std::string &delim)
{
  std::string str;
  bool first = true;
  for (const auto &elem : list) {
    if (first)
      first = false;
    else
      str += delim;

    str += elem;
  }
  return str;
}

std::string hex_format_buffer(const char *buf,
                              size_t size,
                              bool keep_ascii,
                              bool escape_hex)
{
  // Allow enough space for every byte to be sanitized in the form "\x00"
  std::string str(size * 4 + 1, '\0');
  char *s = str.data();

  size_t offset = 0;
  for (size_t i = 0; i < size; i++)
    if (keep_ascii && buf[i] >= 32 && buf[i] <= 126)
      offset += sprintf(s + offset,
                        "%c",
                        (reinterpret_cast<const uint8_t *>(buf))[i]);
    else if (escape_hex)
      offset += sprintf(s + offset,
                        "\\x%02x",
                        (reinterpret_cast<const uint8_t *>(buf))[i]);
    else
      offset += sprintf(s + offset,
                        i == size - 1 ? "%02x" : "%02x ",
                        (reinterpret_cast<const uint8_t *>(buf))[i]);

  // Fit return value to actual length
  str.resize(offset);
  return str;
}

} // namespace bpftrace::util
