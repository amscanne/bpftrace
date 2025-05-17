#include "location.h"

#include <sstream>

#include "ast/context.h"

namespace bpftrace::ast {

SourceLocation::SourceLocation(tokenizer::Position pos, std::shared_ptr<ASTSource> source)
    : position_(pos), source_(std::move(source))
{
}

std::string SourceLocation::filename() const
{
  if (source_) {
    return source_->filename;
  }
  return "";
}

std::string SourceLocation::source_location() const
{
  std::stringstream ss;
  if (source_) {
    ss << source_->filename << ":";
  }
  if (position_.start_line != position_.end_line) {
    ss << position_.start_line << "-" << position_.end_line;
    return ss.str();
  }
  ss << position_.start_line << ":";
  ss << position_.start_column << "-" << position_.end_column;
  return ss.str();
}

std::vector<std::string> SourceLocation::source_context() const
{
  std::vector<std::string> result;

  // Is there source available?
  if (!source_ || position_.start_column == 0) {
    return result;
  }

  // Multi-lines just include all context.
  if (position_.start_line != position_.end_line) {
    assert(position_.start_line < position_.end_line);
    for (unsigned int i = position_.start_line; i <= position_.end_line; i++) {
      assert(i <= source_->lines_.size());
      result.push_back(source_->lines_[i - 1]);
    }
    return result;
  }

  // Single line includes just the relevant context.
  if (position_.start_line > source_->lines_.size()) {
    return result; // Nothing available.
  }
  auto &srcline = source_->lines_[position_.start_line - 1];
  std::stringstream orig;
  for (auto c : srcline) {
    if (c == '\t')
      orig << "    ";
    else
      orig << c;
  }
  result.emplace_back(orig.str());

  std::stringstream select;
  for (unsigned int x = 0; x < srcline.size() && x < position_.end_column - 1;
       x++) {
    char marker = x < position_.start_column - 1 ? ' ' : '~';
    if (srcline[x] == '\t') {
      select << std::string(4, marker);
    } else {
      select << marker;
    }
  }
  result.emplace_back(select.str());

  return result;
}

Location operator+(const Location &orig, const Location &expansion)
{
  if (expansion == nullptr) {
    return orig;
  }
  if (orig == nullptr) {
    return expansion;
  }
  auto nlink = std::make_shared<LocationChain>(expansion->current);
  nlink->parent.emplace(LocationChain::Context(Location(orig)));
  nlink->parent->msg << "expanded from";
  return nlink;
}

} // namespace bpftrace::ast
