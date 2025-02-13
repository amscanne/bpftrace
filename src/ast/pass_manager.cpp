#include "ast/pass_manager.h"

#include "log.h"

namespace bpftrace::ast {

std::atomic<int> PassContext::next_type_id_;
std::unordered_map<int, std::string> PassContext::type_names_;

void PassContext::fail(int type_id)
{
  // Rely on the type being available, otherwise how did we get here?
  LOG(BUG) << "get<" << lookup_type(type_id)
           << "> failed; no object available.";
  __builtin_unreachable();
}

void PassManager::add(Pass &&pass)
{
  // Check that the inputs are all available.
  for (const int type_id : pass.inputs()) {
    if (!outputs_.contains(type_id)) {
      auto type_name = PassContext::lookup_type(type_id);
      LOG(BUG) << "Pass " << pass.name() << " requires output " << type_name
               << ", which is not available.";
    }
  }
  // Check that the registered output is unique.
  const int pass_id = passes_.size();
  for (const int type_id : pass.outputs()) {
    if (outputs_.contains(type_id)) {
      auto &orig_pass = passes_[outputs_[type_id]];
      auto type_name = PassContext::lookup_type(type_id);
      LOG(BUG) << "Pass " << pass.name() << " attempting to register output "
               << type_name << ", which is already registered by pass "
               << orig_pass.name() << ".";
    }
    // Register the output.
    outputs_.emplace(type_id, pass_id);
  }
  // Add the actual pass.
  passes_.emplace_back(std::move(pass));
}

ErrorOrSuccess PassManager::foreach(
    std::function<ErrorOrSuccess(const Pass &)> fn)
{
  Diagnostics warnings;
  for (const auto &pass : passes_) {
    auto err = fn(pass);
    if (!err.ok()) {
      // Return the set of errors with any additional warnings that may have
      // been generated by previous passes.
      return ErrorOrSuccess(err, std::move(warnings));
    }
    // We don't care about the return result here (it must be `ErrorOrSuccess`,
    // but we unwrap all generated warnings into our list above.
    err.unwrap(warnings);
  }
  return Success(std::move(warnings));
}

} // namespace bpftrace::ast
