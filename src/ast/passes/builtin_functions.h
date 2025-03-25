#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// This requires and modifies the `FunctionRegistry` that should be found
// within the pass. It should be injected manually into the pass manager.
Pass CreateBuiltinFunctionsPass();

} // namespace bpftrace::ast
