#include <algorithm>
#include <string>

#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "log.h"
#include "output.h"
#include "required_resources.h"
#include "types_format.h"
#include "util/format.h"
#include "util/stats.h"

namespace libbpf {
#define __BPF_NAME_FN(x) #x
const char *bpf_func_name[] = { __BPF_FUNC_MAPPER(__BPF_NAME_FN) };
#undef __BPF_NAME_FN
} // namespace libbpf

namespace bpftrace {

char TypeFormatError::ID;

void TypeFormatError::log(llvm::raw_ostream &OS) const
{
  OS << "unable to convert type: " << typestr(ty_);
}

// Translate the index into the starting value for the corresponding interval.
// Each power of 2 is mapped into N = 2**k intervals, each of size
// S = 1 << ((index >> k) - 1), and starting at S * N.
// The last k bits of index indicate which interval we want.
//
// For example, if k = 2 and index = 0b11011 (27) we have:
// - N = 2**2 = 4;
// - interval size S is 1 << ((0b11011 >> 2) - 1) = 1 << (6 - 1) = 32
// - starting value is S * N = 128
// - the last 2 bits 11 indicate the third interval so the
//   starting value is 128 + 32*3 = 224
static std::string hist_index_label(uint32_t index, uint32_t k)
{
  const uint32_t n = (1 << k);
  const uint32_t interval = index & (n - 1);
  assert(index >= n);
  uint32_t power = (index >> k) - 1;
  // Choose the suffix for the largest power of 2^10
  const uint32_t decade = power / 10;
  const char suffix = "\0KMGTPE"[decade];
  power -= 10 * decade;

  std::ostringstream label;
  label << (1 << power) * (n + interval);
  if (suffix)
    label << suffix;
  return label.str();
}

static std::string lhist_index_label(int number, int step)
{
  constexpr int kilo = 1024;
  constexpr int mega = 1024 * 1024;

  if (step % kilo != 0)
    return std::to_string(number);

  std::ostringstream label;

  if (number == 0) {
    label << number;
  } else if (number % mega == 0) {
    label << number / mega << 'M';
  } else if (number % kilo == 0) {
    label << number / kilo << 'K';
  } else {
    label << number;
  }

  return label.str();
}

static void hist_prepare(const std::vector<uint64_t> &values,
                         int &min_index,
                         int &max_index,
                         int &max_value)
{
  min_index = -1;
  max_index = -1;
  max_value = 0;

  for (size_t i = 0; i < values.size(); i++) {
    int v = values.at(i);
    if (v > 0) {
      if (min_index == -1)
        min_index = i;
      max_index = i;
    }
    max_value = std::max(v, max_value);
  }
}

static void lhist_prepare(const std::vector<uint64_t> &values,
                          int min,
                          int max,
                          int step,
                          int &max_index,
                          int &max_value,
                          int &buckets,
                          int &start_value,
                          int &end_value)
{
  max_index = -1;
  max_value = 0;
  buckets = (max - min) / step; // excluding lt and gt buckets

  for (size_t i = 0; i < values.size(); i++) {
    int v = values.at(i);
    if (v != 0)
      max_index = i;
    max_value = std::max(v, max_value);
  }

  if (max_index == -1)
    return;

  // trim empty values
  start_value = -1;
  end_value = 0;

  for (unsigned int i = 0; i <= static_cast<unsigned int>(buckets) + 1; i++) {
    if (values.at(i) > 0) {
      if (start_value == -1) {
        start_value = i;
      }
      end_value = i;
    }
  }

  if (start_value == -1) {
    start_value = 0;
  }
}

Result<output::Value> format(BPFtrace &bpftrace,
                             const SizedType &type,
                             const std::vector<uint8_t> &value,
                             bool is_per_cpu,
                             uint32_t div)
{
  uint32_t nvalues = is_per_cpu ? bpftrace.ncpus_ : 1;
  switch (type.GetTy()) {
    case Type::kstack_t: {
      return bpftrace.get_stack(util::read_data<uint64_t>(value.data()),
                                util::read_data<uint64_t>(value.data() + 8),
                                -1,
                                -1,
                                false,
                                type.stack_type,
                                8);
    }
    case Type::ustack_t: {
      return bpftrace.get_stack(util::read_data<uint64_t>(value.data()),
                                util::read_data<uint64_t>(value.data() + 8),
                                util::read_data<int32_t>(value.data() + 16),
                                util::read_data<int32_t>(value.data() + 20),
                                true,
                                type.stack_type,
                                8);
    }
    case Type::ksym_t: {
      return bpftrace.resolve_ksym(util::read_data<uint64_t>(value.data()));
    }
    case Type::usym_t: {
      return bpftrace.resolve_usym(util::read_data<uint64_t>(value.data()),
                                   util::read_data<uint32_t>(value.data() + 8),
                                   util::read_data<uint32_t>(value.data() +
                                                             12));
    }
    case Type::inet: {
      return bpftrace.resolve_inet(util::read_data<uint64_t>(value.data()),
                                   static_cast<const uint8_t *>(value.data() +
                                                                8));
    }
    case Type::username: {
      return bpftrace.resolve_uid(util::read_data<uint64_t>(value.data()));
    }
    case Type::buffer: {
      return bpftrace.resolve_buf(
          reinterpret_cast<const AsyncEvent::Buf *>(value.data())->content,
          reinterpret_cast<const AsyncEvent::Buf *>(value.data())->length);
    }
    case Type::string: {
      const auto *p = reinterpret_cast<const char *>(value.data());
      return std::string(p, strnlen(p, type.GetSize()));
    }
    case Type::array: {
      size_t elem_size = type.GetElementTy()->GetSize();
      std::vector<output::Value> elems;
      for (size_t i = 0; i < type.GetNumElements(); i++) {
        std::vector<uint8_t> elem_data(value.begin() + i * elem_size,
                                       value.begin() + (i + 1) * elem_size);
        auto val = format(
            bpftrace, *type.GetElementTy(), elem_data, is_per_cpu, div);
        if (!val) {
          return val.takeError();
        }
        if (!std::holds_alternative<output::Primitive>(val->variant)) {
          return make_error<TypeFormatError>(type);
        }
        elems.emplace_back(
            std::move(std::get<output::Primitive>(val->variant)));
      }
      return elems;
    }
    case Type::record: {
      std::map<std::string, output::Primitive> fields;
      for (auto &field : type.GetFields()) {
        std::vector<uint8_t> elem_data(value.begin() + field.offset,
                                       value.begin() + field.offset +
                                           field.type.GetSize());
        auto val = format(bpftrace, field.type, elem_data, is_per_cpu, div);
        if (!val) {
          return val.takeError();
        }
        if (!std::holds_alternative<output::Primitive>(val->variant)) {
          return make_error<TypeFormatError>(type);
        }
        fields.emplace(field.name,
                       std::move(std::get<output::Primitive>(val->variant)));
      }
      return fields;
    }
    case Type::tuple: {
      std::vector<output::Primitive> elems;
      for (auto &field : type.GetFields()) {
        std::vector<uint8_t> elem_data(value.begin() + field.offset,
                                       value.begin() + field.offset +
                                           field.type.GetSize());
        auto val = format(
            bpftrace, field.type, elem_data, is_per_cpu, div, false);
        if (!val) {
          return val.takeError();
        }
        if (!std::holds_alternative<output::Primitive>(val->variant)) {
          return make_error<TypeFormatError>(type);
        }
        elems.push_back(std::get<output::Primitive>(val->variant));
      }
      return elems;
    }
    case Type::count_t: {
      return util::reduce_value<uint64_t>(value, nvalues) / div;
    }
    case Type::avg_t: {
      // on this code path, avg is calculated in the kernel while
      // printing the entire map is handled in a different function
      // which shouldn't call this
      assert(!is_per_cpu);
      if (type.IsSigned()) {
        return util::read_data<int64_t>(value.data()) / div;
      }
      return util::read_data<uint64_t>(value.data()) / div;
    }
    case Type::integer: {
      auto sign = type.IsSigned();
      switch (type.GetIntBitWidth()) {
          // clang-format off
          case 64:
            if (sign)
              return util::reduce_value<int64_t>(value, nvalues) / static_cast<int64_t>(div);
            return util::reduce_value<uint64_t>(value, nvalues) / div;
          case 32:
            if (sign)
              return std::to_string(
                  util::reduce_value<int32_t>(value, nvalues) / static_cast<int32_t>(div));
            return util::reduce_value<uint32_t>(value, nvalues) / div;
          case 16:
            if (sign)
              return 
                  util::reduce_value<int16_t>(value, nvalues) / static_cast<int16_t>(div);
            return util::reduce_value<uint16_t>(value, nvalues) / div;
          case 8:
            if (sign)
              return 
                  util::reduce_value<int8_t>(value, nvalues) / static_cast<int8_t>(div);
            return util::reduce_value<uint8_t>(value, nvalues) / div;
          // clang-format on
        default:
          // This type cannot be handled.
          return make_error<TypeFormatError>(type);
      }
    }
    case Type::sum_t: {
      if (type.IsSigned())
        return util::reduce_value<int64_t>(value, nvalues) / div;
      return util::reduce_value<uint64_t>(value, nvalues) / div;
    }
    case Type::max_t:
    case Type::min_t: {
      if (is_per_cpu) {
        if (type.IsSigned()) {
          return util::min_max_value<int64_t>(value, nvalues, type.IsMaxTy()) /
                 div;
        }
        return util::min_max_value<uint64_t>(value, nvalues, type.IsMaxTy()) /
               div;
      }
      if (type.IsSigned()) {
        return util::read_data<int64_t>(value.data()) / div;
      }
      return util::read_data<uint64_t>(value.data()) / div;
    }
    case Type::timestamp: {
      return bpftrace.resolve_timestamp(
          reinterpret_cast<const AsyncEvent::Strftime *>(value.data())->mode,
          reinterpret_cast<const AsyncEvent::Strftime *>(value.data())
              ->strftime_id,
          reinterpret_cast<const AsyncEvent::Strftime *>(value.data())->nsecs);
    }
    case Type::mac_address: {
      return bpftrace.resolve_mac_address(value.data());
    }
    case Type::cgroup_path_t: {
      return bpftrace.resolve_cgroup_path(
          reinterpret_cast<const AsyncEvent::CgroupPath *>(value.data())
              ->cgroup_path_id,
          reinterpret_cast<const AsyncEvent::CgroupPath *>(value.data())
              ->cgroup_id);
    }
    case Type::strerror_t: {
      return strerror(util::read_data<uint64_t>(value.data()));
    }
    default:
      return make_error<TypeFormatError>(type);
  }
}

static Result<output::Value> map_contents(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key)
{
  std::map<output::Primitive, output::Value> rval;
  uint32_t i = 0;
  size_t total = values_by_key.size();
  const auto &map_info = bpftrace.resources.maps_info.at(map.name());
  const auto &key_type = map_info.key_type;
  const auto &value_type = map_info.value_type;

  for (const auto &pair : values_by_key) {
    auto &key_data = pair.first;
    auto &value_data = pair.second;

    if (top) {
      if (total > top && i++ < (total - top))
        continue;
    }
    auto key_res = format(
        bpftrace, key_type, key_data, map.is_per_cpu_type(), div);
    if (!key_res) {
      return key_res.takeError();
    }
    auto value_res = format(
        bpftrace, value_type, value_data, map.is_per_cpu_type(), div);
    if (!value_res) {
      return value_res.takeError();
    }
    rval.emplace(std::move(*key_res), std::move(*value_res));
  }
  return rval;
}

static Result<output::Value> map_hist_contents(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
        &total_counts_by_key)
{
  uint32_t i = 0;
  const auto &map_info = bpftrace.resources.maps_info.at(map.name());
  const auto &map_type = map_info.value_type;
  bool first = true;
  for (const auto &key_count : total_counts_by_key) {
    const auto &key = key_count.first;
    const auto &value = values_by_key.at(key);

    if (top && values_by_key.size() > top && i++ < (values_by_key.size() - top))
      continue;

    if (first)
      first = false;
    else
      map_elem_delim(map_type);

    auto key_str = map_key_to_str(bpftrace, map, key);
    std::string val_str;
    if (map_type.IsHistTy()) {
      if (!std::holds_alternative<HistogramArgs>(map_info.detail))
        LOG(BUG) << "call to hist with missing \"bits\" argument";
      val_str = hist_to_str(value,
                            div,
                            std::get<HistogramArgs>(map_info.detail).bits);
    } else {
      if (!std::holds_alternative<LinearHistogramArgs>(map_info.detail))
        LOG(BUG) << "call to lhist with missing arguments";
      const auto &args = std::get<LinearHistogramArgs>(map_info.detail);
      val_str = lhist_to_str(value, args.min, args.max, args.step);
    }
    map_key_val(map_type, key_str, val_str);
  }
}

static Result<output::Value> map_stats_contents(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key)
{
  const auto &map_type = bpftrace.resources.maps_info.at(map.name()).value_type;
  uint32_t i = 0;
  size_t total = values_by_key.size();
  bool first = true;

  for (const auto &[key, value] : values_by_key) {
    if (top && map_type.IsAvgTy()) {
      if (total > top && i++ < (total - top))
        continue;
    }

    if (first)
      first = false;
    else
      map_elem_delim(map_type);

    auto key_str = map_key_to_str(bpftrace, map, key);

    std::string total_str;
    std::string count_str;
    std::string avg_str;

    if (map_type.IsSigned()) {
      auto stats = util::stats_value<int64_t>(value, bpftrace.ncpus_);
      avg_str = std::to_string(stats.avg / div);
      total_str = std::to_string(stats.total);
      count_str = std::to_string(stats.count);
    } else {
      auto stats = util::stats_value<uint64_t>(value, bpftrace.ncpus_);
      avg_str = std::to_string(stats.avg / div);
      total_str = std::to_string(stats.total);
      count_str = std::to_string(stats.count);
    }

    std::string value_str;
    if (map_type.IsStatsTy()) {
      std::vector<std::pair<std::string, std::string>> stats = {
        { "count", std::move(count_str) },
        { "average", std::move(avg_str) },
        { "total", std::move(total_str) }
      };
      value_str = key_value_pairs_to_str(stats);
    } else {
      value_str = std::move(avg_str);
    }

    map_key_val(map_type, key_str, value_str);
  }
}

std::string TextOutput::hist_to_str(const std::vector<uint64_t> &values,
                                    uint32_t div,
                                    uint32_t k) const
{
  int min_index, max_index, max_value;
  hist_prepare(values, min_index, max_index, max_value);
  if (max_index == -1)
    return "";

  std::ostringstream res;
  for (int i = min_index; i <= max_index; i++) {
    std::ostringstream header;

    // Index 0 is for negative values. Following that, each sequence
    // of N = 1 << k indexes represents one power of 2.
    // In particular:
    // - the first set of N indexes is for values 0..N-1
    //   (one value per index)
    // - the second and following sets of N indexes each contain
    //   <1, 2, 4 .. and subsequent powers of 2> values per index.
    //
    // Since the first and second set are closed intervals and the value
    // of each interval equals "index - 1", we print it directly.
    // Higher indexes contain multiple values and we use helpers to print
    // the range as open intervals.

    if (i == 0) {
      header << "(..., 0)";
    } else if (i <= (2 << k)) {
      header << "[" << (i - 1) << "]";
    } else {
      // Use a helper function to print the interval boundaries.
      header << "[" << hist_index_label(i - 1, k);
      header << ", " << hist_index_label(i, k) << ")";
    }

    int max_width = 52;
    int bar_width = values.at(i) / static_cast<float>(max_value) * max_width;
    std::string bar(bar_width, '@');

    res << std::setw(16) << std::left << header.str() << std::setw(8)
        << std::right << (values.at(i) / div) << " |" << std::setw(max_width)
        << std::left << bar << "|" << std::endl;
  }
  return res.str();
}

std::string TextOutput::lhist_to_str(const std::vector<uint64_t> &values,
                                     int min,
                                     int max,
                                     int step) const
{
  int max_index, max_value, buckets, start_value, end_value;
  lhist_prepare(values,
                min,
                max,
                step,
                max_index,
                max_value,
                buckets,
                start_value,
                end_value);
  if (max_index == -1)
    return "";

  std::ostringstream res;
  for (int i = start_value; i <= end_value; i++) {
    int max_width = 52;
    int bar_width = values.at(i) / static_cast<float>(max_value) * max_width;
    std::ostringstream header;
    if (i == 0) {
      header << "(..., " << lhist_index_label(min, step) << ")";
    } else if (i == (buckets + 1)) {
      header << "[" << lhist_index_label(max, step) << ", ...)";
    } else {
      header << "[" << lhist_index_label(((i - 1) * step) + min, step);
      header << ", " << lhist_index_label((i * step) + min, step) << ")";
    }

    std::string bar(bar_width, '@');

    res << std::setw(16) << std::left << header.str() << std::setw(8)
        << std::right << values.at(i) << " |" << std::setw(max_width)
        << std::left << bar << "|" << std::endl;
  }
  return res.str();
}

std::string TextOutput::value_to_str(BPFtrace &bpftrace,
                                     const SizedType &type,
                                     const std::vector<uint8_t> &value,
                                     bool is_per_cpu,
                                     uint32_t div,
                                     bool is_map_key) const
{
  switch (type.GetTy()) {
    case Type::pointer: {
      std::ostringstream res;
      res << "0x" << std::hex << util::read_data<uint64_t>(value.data());
      return res.str();
    }
    case Type::integer: {
      if (type.IsEnumTy() && div == 1) {
        assert(!is_per_cpu);

        const auto *data = value.data();
        const auto &enum_name = type.GetName();
        uint64_t enum_val;
        switch (type.GetIntBitWidth()) {
          case 64:
            enum_val = util::read_data<uint64_t>(data);
            break;
          case 32:
            enum_val = util::read_data<uint32_t>(data);
            break;
          case 16:
            enum_val = util::read_data<uint16_t>(data);
            break;
          case 8:
            enum_val = util::read_data<uint8_t>(data);
            break;
          default:
            LOG(BUG) << "value_to_str: Invalid int bitwidth: "
                     << type.GetIntBitWidth() << "provided";
            return {};
        }

        if (c_definitions_.enum_defs.contains(enum_name) &&
            c_definitions_.enum_defs[enum_name].contains(enum_val)) {
          return c_definitions_.enum_defs[enum_name][enum_val];
        } else {
          // Fall back to something comprehensible in case user somehow
          // tricked the type system into accepting an invalid enum.
          return std::to_string(enum_val);
        }
      }
      [[fallthrough]];
    }
    default: {
      return Output::value_to_str(
          bpftrace, type, value, is_per_cpu, div, is_map_key);
    }
  };
}

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

std::string TextOutput::map_key_to_str(BPFtrace &bpftrace,
                                       const BpfMap &map,
                                       const std::vector<uint8_t> &key) const
{
  const auto &map_info = bpftrace.resources.maps_info.at(map.name());
  const auto &key_type = map_info.key_type;
  if (map_info.is_scalar)
    return map.name();

  return map.name() + "[" + map_key_str(bpftrace, key_type, key) + "]";
}

void TextOutput::map_key_val(const SizedType &map_type,
                             const std::string &key,
                             const std::string &val) const
{
  out_ << key;
  if (map_type.IsHistTy() || map_type.IsLhistTy())
    out_ << ":\n";
  else
    out_ << ": ";
  out_ << val;
}

void TextOutput::map_elem_delim(const SizedType &map_type) const
{
  if (!map_type.IsKstackTy() && !map_type.IsUstackTy() &&
      !map_type.IsKsymTy() && !map_type.IsUsymTy() && !map_type.IsInetTy())
    out_ << "\n";
}

std::string TextOutput::key_value_pairs_to_str(
    std::vector<std::pair<std::string, std::string>> &keyvals) const
{
  std::vector<std::string> elems;
  for (auto &e : keyvals)
    elems.push_back(e.first + " " + e.second);
  return util::str_join(elems, ", ");
}

static void json_emit(std::ostream &out, const std::string &s)
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

std::string JsonOutput::hist_to_str(const std::vector<uint64_t> &values,
                                    uint32_t div,
                                    uint32_t k) const
{
  int min_index, max_index, max_value;
  hist_prepare(values, min_index, max_index, max_value);
  if (max_index == -1)
    return "[]";

  std::ostringstream res;
  res << "[";
  for (int i = min_index; i <= max_index; i++) {
    if (i > min_index)
      res << ", ";

    res << "{";
    // See description in TextOutput::hist_to_str():
    // first index is for negative values, the next 2 sets of
    // N = 2^k indexes have one value each (equal to i -1)
    // and remaining sets of N indexes each cover one power of 2,
    // whose ranges are computed as described in hist_index_label()
    if (i == 0) {
      res << "\"max\": -1, ";
    } else if (i <= (2 << k)) {
      res << "\"min\": " << i - 1 << ", \"max\": " << i - 1 << ", ";
    } else {
      const uint32_t n = 1 << k;
      uint32_t power = ((i - 1) >> k) - 1;
      uint32_t bucket = (i - 1) & (n - 1);
      const long low = (1ULL << power) * (n + bucket);
      power = (i >> k) - 1;
      bucket = i & (n - 1);
      const long high = ((1ULL << power) * (n + bucket)) - 1;
      res << "\"min\": " << low << ", \"max\": " << high << ", ";
    }
    res << "\"count\": " << values.at(i) / div;
    res << "}";
  }
  res << "]";

  return res.str();
}

std::string JsonOutput::lhist_to_str(const std::vector<uint64_t> &values,
                                     int min,
                                     int max,
                                     int step) const
{
  int max_index, max_value, buckets, start_value, end_value;
  lhist_prepare(values,
                min,
                max,
                step,
                max_index,
                max_value,
                buckets,
                start_value,
                end_value);
  if (max_index == -1)
    return "[]";

  std::ostringstream res;
  res << "[";
  for (int i = start_value; i <= end_value; i++) {
    if (i > start_value)
      res << ", ";

    res << "{";
    if (i == 0) {
      res << "\"max\": " << min - 1 << ", ";
    } else if (i == (buckets + 1)) {
      res << "\"min\": " << max << ", ";
    } else {
      long low = ((i - 1) * step) + min;
      long high = (i * step) + min - 1;
      res << "\"min\": " << low << ", \"max\": " << high << ", ";
    }
    res << "\"count\": " << values.at(i);
    res << "}";
  }
  res << "]";

  return res.str();
}

void JsonOutput::map_hist(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::map<std::vector<uint8_t>, std::vector<uint64_t>> &values_by_key,
    const std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
        &total_counts_by_key) const
{
  if (total_counts_by_key.empty())
    return;

  const auto &map_info = bpftrace.resources.maps_info.at(map.name());

  out_ << R"({"type": ")" << MessageType::hist << R"(", "data": {)";
  out_ << "\"" << json_escape(map.name()) << "\": ";
  if (!map_info.is_scalar)
    out_ << "{";

  map_hist_contents(
      bpftrace, map, top, div, values_by_key, total_counts_by_key);

  if (!map_info.is_scalar)
    out_ << "}";
  out_ << "}}" << std::endl;
}

void JsonOutput::map_stats(
    BPFtrace &bpftrace,
    const BpfMap &map,
    uint32_t top,
    uint32_t div,
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key) const
{
  if (values_by_key.empty())
    return;

  const auto &map_info = bpftrace.resources.maps_info.at(map.name());

  out_ << R"({"type": ")" << MessageType::stats << R"(", "data": {)";
  out_ << "\"" << json_escape(map.name()) << "\": ";
  if (!map_info.is_scalar)
    out_ << "{";

  map_stats_contents(bpftrace, map, top, div, values_by_key);

  if (!map_info.is_scalar)
    out_ << "}";
  out_ << "}}" << std::endl;
}

} // namespace bpftrace
