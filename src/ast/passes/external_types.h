#pragma once

#include "ast/pass_manager.h"

namespace bpftrace::ast {

ast::Pass CreateDefineExternalTypesPass();

} // namespace bpftrace::ast
