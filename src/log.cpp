#include "log.h"

#include <unistd.h>

namespace bpftrace {

std::string logtype_str(LogType t, bool colorize)
{
  if (colorize) {
    switch (t) {
        // clang-format off
      case LogType::DEBUG   : return "";
      case LogType::V1      : return "";
      case LogType::HINT    : return "\033[33mHINT:\033[0m ";
      case LogType::WARNING : return "\033[34mWARNING:\033[0m ";
      case LogType::ERROR   : return "\033[31mERROR:\033[0m ";
      case LogType::BUG     : return "\033[31mBUG:\033[0m ";
        // clang-format on
    }
  } else {
    switch (t) {
        // clang-format off
      case LogType::DEBUG   : return "";
      case LogType::V1      : return "";
      case LogType::HINT    : return "HINT: ";
      case LogType::WARNING : return "WARNING: ";
      case LogType::ERROR   : return "ERROR: ";
      case LogType::BUG     : return "BUG: ";
        // clang-format on
    }
  }

  return {}; // unreached
}

Log::Log()
{
  enabled_map_[LogType::DEBUG] = true;
  enabled_map_[LogType::V1] = false;
  enabled_map_[LogType::HINT] = true;
  enabled_map_[LogType::WARNING] = true;
  enabled_map_[LogType::ERROR] = true;
  enabled_map_[LogType::BUG] = true;
}

Log& Log::get()
{
  static Log log;
  return log;
}

void Log::take_input(LogType type,
                     const std::optional<location>& loc,
                     std::ostream& out,
                     bool colorize,
                     std::string&& input)
{
  auto print_out = [&]() {
    out << logtype_str(type, colorize) << input << std::endl;
  };

  if (loc) {
    if (src_.empty()) {
      std::cerr << "Log: cannot resolve location before calling set_source()."
                << std::endl;
      print_out();
    } else if (loc->begin.line == 0) {
      std::cerr << "Log: invalid location." << std::endl;
      print_out();
    } else if (loc->begin.line > loc->end.line) {
      std::cerr << "Log: loc.begin > loc.end: " << loc->begin << ":" << loc->end
                << std::endl;
      print_out();
    } else {
      log_with_location(type, loc.value(), out, colorize, input);
    }
  } else {
    print_out();
  }
}

const std::string Log::get_source_line(unsigned int n)
{
  // Get the Nth source line (N is 0-based). Return an empty string if it
  // doesn't exist
  std::string line;
  std::stringstream ss(src_);
  for (unsigned int idx = 0; idx <= n; idx++) {
    std::getline(ss, line);
    if (ss.eof() && idx == n)
      return line;
    if (!ss)
      return "";
  }
  return line;
}

void Log::log_with_location(LogType type,
                            const location& l,
                            std::ostream& out,
                            bool colorize,
                            const std::string& m)
{
  if (filename_.size()) {
    out << filename_ << ":";
  }

  std::string msg(m);
  const std::string& typestr = logtype_str(type, colorize);

  if (!msg.empty() && msg.back() == '\n') {
    msg.pop_back();
  }

  /* For a multi line error only the line range is printed:
     <filename>:<start_line>-<end_line>: ERROR: <message>
  */
  if (l.begin.line < l.end.line) {
    out << l.begin.line << "-" << l.end.line << ": " << typestr << msg
        << std::endl;
    return;
  }

  /*
    For a single line error the format is:

    <filename>:<line>:<start_col>-<end_col>: ERROR: <message>
    <source line>
    <marker>

    E.g.

    file.bt:1:10-20: error: <message>
    i:s:1   /1 < "str"/
            ~~~~~~~~~~
  */
  out << l.begin.line << ":" << l.begin.column << "-" << l.end.column;
  out << ": " << typestr << msg << std::endl;

  // for bpftrace::position, valid line# starts from 1
  std::string srcline = get_source_line(l.begin.line - 1);

  if (srcline == "")
    return;

  // To get consistent printing all tabs will be replaced with 4 spaces
  for (auto c : srcline) {
    if (c == '\t')
      out << "    ";
    else
      out << c;
  }
  out << std::endl;

  for (unsigned int x = 0;
       x < srcline.size() && x < (static_cast<unsigned int>(l.end.column) - 1);
       x++) {
    char marker = (x < (static_cast<unsigned int>(l.begin.column) - 1)) ? ' '
                                                                        : '~';
    if (srcline[x] == '\t') {
      out << std::string(4, marker);
    } else {
      out << marker;
    }
  }
  out << std::endl;
}

static bool shouldColorize(std::ostream* out)
{
  // As a special case, if we are emitting to std::cerr (implementation-defined
  // wrapping of the stderr FILE* stream) and this is connected to a terminal
  // then we emit colors. Note that the user could pass a construct separately
  // that points to stderr, but anything outside the default constructor we
  // will just emit the strings without the control codes.
  std::cerr << "cerr == " << reinterpret_cast<long>(&std::cerr) << "\n";
  std::cerr << "out == " << reinterpret_cast<long>(out) << "\n";
  return true; // (&out == &cerr) && isatty(fileno(stderr));
}

LogStream::LogStream(const std::string& file,
                     int line,
                     LogType type,
                     std::ostream* out)
    : sink_(Log::get()),
      type_(type),
      loc_(std::nullopt),
      out_(*out),
      colorize_(shouldColorize(out)),
      log_file_(file),
      log_line_(line)
{
}

LogStream::LogStream(const std::string& file,
                     int line,
                     LogType type,
                     const location& loc,
                     std::ostream* out)
    : sink_(Log::get()),
      type_(type),
      loc_(loc),
      out_(*out),
      colorize_(shouldColorize(out)),
      log_file_(file),
      log_line_(line)
{
}

LogStream::~LogStream()
{
#ifdef FUZZ
  // When fuzzing, we don't want to output error messages. However, some
  // function uses a error message length to determine whether if an error
  // occur. So, we cannot simply DISABLE_LOG(ERROR). Instead, here, we don't
  // output error messages to stderr.
  if (sink_.is_enabled(type_) &&
      (type_ != LogType::ERROR ||
       (&out_ != &std::cout && &out_ != &std::cerr))) {
#else
  if (sink_.is_enabled(type_)) {
#endif
    auto msg = buf_.str();
    if (type_ == LogType::DEBUG)
      msg = internal_location() + msg;

    sink_.take_input(type_, loc_, out_, colorize_, std::move(msg));
  }
}

std::string LogStream::internal_location()
{
  std::ostringstream ss;
  ss << "[" << log_file_ << ":" << log_line_ << "] ";
  return ss.str();
}

[[noreturn]] LogStreamBug::~LogStreamBug()
{
  sink_.take_input(
      type_, loc_, out_, colorize_, internal_location() + buf_.str());
  abort();
}

}; // namespace bpftrace
