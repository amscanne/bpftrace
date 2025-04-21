#pragma once

namespace bpftrace::parser {

class Position {
public:
  unsigned int start_line = 1;
  unsigned int start_column = 1;
  unsigned int end_line = 1;
  unsigned int end_column = 1;

  Position operator+(const Position &other) {
    Position result;
    if (start_line < other.start_line) {
      result.start_line = start_line;
      result.start_column = start_column;
    } else if (start_line == other.start_line) {
      result.start_line = start_line;
      result.start_column = std::min(result.start_column, other.start_column);
    } else {
      result.start_line = other.start_line;
      result.start_column = other.start_column;
    }
    if (end_line > other.end_line) {
      result.end_line = end_line;
      result.end_column = end_column;
    } else if (end_line == other.end_line) {
      result.end_line = end_line;
      result.end_column = std::max(result.end_column, other.end_column);
    } else {
      result.end_line = other.end_line;
      result.end_column = other.end_column;
    }
    return result;
  }
};

} // namespace bpftrace::parser
