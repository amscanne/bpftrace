#include "stdlib/avg.h"

// Use the `avg_t` name within script.
typedef struct avg avg_t;

// Export the __avg_combine function for use in BPF programs.
void __avg_aggregate(avg_t *dst, const avg_t *src) { __avg_combine(dst, src); }