#pragma once

#include <fstream>
#include <string>

#include "util/result.h"

namespace bpftrace {

class TracepointFormatFileError : public ErrorInfo<TracepointFormatFileError> {
public:
  static char ID;
  TracepointFormatFileError(std::string category,
                            std::string event,
                            std::string file_path)
      : category_(std::move(category)),
        event_(std::move(event)),
        file_path_(std::move(file_path)) {};
  void log(llvm::raw_ostream &OS) const override;
  std::string err() const;
  std::string hint() const;

private:
  std::string category_;
  std::string event_;
  std::string file_path_;
};

class TracepointFormatParser {
public:
  TracepointFormatParser(std::string category,
                         std::string event)
      : category_(std::move(category)),
        event_(std::move(event)) {};

  Result<> parse_format_file();
  std::string get_tracepoint_struct();

protected:
  std::string get_tracepoint_struct(std::istream &format_file);

private:
   std::string parse_field(const std::string &line, int *last_offset);

  const std::string category_;
  const std::string event_;
  std::ifstream format_file_;
};

} // namespace bpftrace
