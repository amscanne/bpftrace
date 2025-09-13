#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// Sentinel value guarnateeing all paths have returns injected.
//
// All modifications are made directly in the AST, this state may
// be used to check that the pass has been completed successfully.
class ReturnPathsChecked : public State<"return-paths"> {};

Pass CreateReturnPathPass();

} // namespace bpftrace::ast
