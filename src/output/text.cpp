#include <iomanip>
#include <string>

#include "output/json.h"

namespace bpftrace::output {

static void emit_json(std::ostream &out, const bool &v)
{
  if (v) {
    out << "true";
  } else {
    out << "false";
  }
}

template <typename T>
  requires(std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t> ||
           std::is_same_v<T, double>)
static void emit_json(std::ostream &out, const T &v)
{
  // JSON does not support numbers other than floating point, therefore
  // we emit int64_t as a string if it is not representable as a 32-bit
  // floating point.
  auto s = std::to_string(v);
  if (static_cast<T>(static_cast<float>(v)) != v) {
    return emit_json(out, s);
  }
  out << s;
}

static void emit_json(std::ostream &out, const std::string &s)
{
  for (const char c : s) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;

      case '\\':
        out << "\\\\";
        break;

      case '\n':
        out << "\\n";
        break;

      case '\r':
        out << "\\r";
        break;

      case '\t':
        out << "\\t";
        break;

      default:
        // c always >= '\x00'
        if (c <= '\x1f') {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(c);
        } else {
          out << c;
        }
    }
  }
}

template <typename T>
  requires(std::is_same_v<T, Primitive> || std::is_same_v<T, Value>)
static void emit_json(std::ostream &out, const T &v)
{
  std::visit([&](const auto &v) { emit_json(out, v); }, v.variant);
}

template <typename T>
static void emit_json(std::ostream &out, const std::vector<T> &v)
{
  out << "[";
  bool first = true;
  for (const auto &elem : v) {
    if (!first) {
      out << ",";
    }
    emit_json(out, elem);
    first = false;
  }
  out << "]";
}

template <typename K, typename V>
static void emit_json(std::ostream &out, const std::map<K, V> &v)
{
  out << "{";
  bool first = true;
  for (const auto &[key, elem] : v) {
    if (!first) {
      out << ",";
    }
    emit_json(out, key);
    out << ":";
    emit_json(out, v);
    first = false;
  }
  out << "}";
}

void JsonOutput::emit(const Value &v)
{
  emit_json(out_, v);
}

void JsonOutput::emit(const Message &m)
{
  switch (m.type) {
    case Message::Type::lost_events:
      out_ << "Lost " << lost << " events" << std::endl;
      break;
    case Message::Type::attached_probes:
      if (num_probes == 1)
        out_ << "Attached " << num_probes << " probe" << std::endl;
      else
        out_ << "Attached " << num_probes << " probes" << std::endl;
      break;
  }

  void TextOutput::helper_error(int retcode, const HelperErrorInfo &info) const
  {
    LOG(WARNING,
        std::string(info.source_location),
        std::vector(info.source_context),
        out_)
        << get_helper_error_msg(info.func_id, retcode)
        << "\nAdditional Info - helper: " << libbpf::bpf_func_name[info.func_id]
        << ", retcode: " << retcode;
  }
  out_ << R"({"type":")" << m.type << R"(", "data":)";
  emit(m.value);
  out_ << "}";
}

} // namespace bpftrace::output
