#include <cmath>

#include "stdlib/avg.h"
#include "stdlib/stdlib.h"

namespace bpftrace::stdlib {

class AvgType : public TypeImpl<"avg_t"> {
public:
  static std::optional<std::string> bpf_aggregate()
  {
    return "__avg_aggregate"; // Defined in `avg.bpf.c`.
  }
  void aggregate(Value &dst, const Value &src) const override
  {
    auto &dst_avg = dst.data<struct avg>();
    const auto &src_avg = src.data<struct avg>();
    __avg_combine(&dst_avg, &src_avg);
  }
  OutputVariant format(const Value &val) const override
  {
    const auto &avg = val.data<struct avg>();
    if (avg.count == 0) {
      return NAN;
    } else {
      return static_cast<double>(avg.sum) / static_cast<double>(avg.count);
    }
  }
};

static AvgType::Factory _;

} // namespace bpftrace::stdlib
