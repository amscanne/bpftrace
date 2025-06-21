#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct avg {
  long long sum;
  long long count;
};

inline void __avg_combine(struct avg *dst, const struct avg *src)
{
  dst->sum += src->sum;
  dst->count += src->count;
}

#ifdef __cplusplus
}
#endif
