#pragma once

#include <optional>
#include <sstream>
#include <vector>

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "bpftrace.h"

namespace bpftrace::ast {

class AttachPointParseError : ErrorInfo<AttachPointParseError> {
public:
  static char ID;
  AttachPointParseError() {};
  void log(llvm::raw_ostream &OS) const override {
    OS << ss_.str();
  }

  template <typename T>
  AttachPointParseError& operator<<(AttachPointParseError& out, const T &other) {
    ss_ << other;
    return *this;
  }

private:
  std::stringstream ss_;
};

class AttachPointParser {
public:
  AttachPointParser(BPFtrace &bpftrace, bool listing);
  ~AttachPointParser() = default;

  // Parse an attachpoint in a list.
  Result<AttachPointList> parse(ASTContext &ast, const std::string &raw);

private:
  enum State { OK = 0, INVALID, NEW_APS, SKIP };

  // This method splits an attach point definition into arguments,
  // where arguments are separated by `:`. The exception is `:`s inside
  // of quoted strings, which we must treat as a literal.
  //
  // This method also resolves positional parameters. Positional params
  // may be escaped with double quotes.
  //
  // Note that this function assumes the raw string is generally well
  // formed. More specifically, that there is no unescaped whitespace
  // and no unmatched quotes.
  Result<std::vector<std::string>> lex(const std::string &raw);

  State special_parser();
  State kprobe_parser(bool allow_offset = true);
  State kretprobe_parser();
  State uprobe_parser(bool allow_offset = true, bool allow_abs_addr = true);
  State uretprobe_parser();
  State usdt_parser();
  State tracepoint_parser();
  State profile_parser();
  State interval_parser();
  State software_parser();
  State hardware_parser();
  State watchpoint_parser(bool async = false);
  State fentry_parser();
  State iter_parser();
  State raw_tracepoint_parser();

  State argument_count_error(int expected,
                             std::optional<int> expected2 = std::nullopt);
  std::optional<uint64_t> stoull(const std::string &str);
  std::optional<int64_t> stoll(const std::string &str);

  std::vector<std::string> parts_;
  AttachPointList new_attach_points;
  bool listing_;
};

// The attachpoints are expanded in their own separate pass.
Pass CreateParseAttachpointsPass(bool listing = false);

} // namespace bpftrace::ast
