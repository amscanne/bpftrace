#include "ast/context.h"

#include "ast/ast.h"
#include "ast/diagnostic.h"

namespace bpftrace::ast {

ASTSource::ASTSource(std::string &&filename, std::string &&input)
    : filename(std::move(filename)), contents(std::move(input))
{
  std::stringstream ss(contents);
  std::string line;
  while (std::getline(ss, line)) {
    lines_.emplace_back(std::move(line));
  }
}

std::string ASTSource::read(const SourceLocation &loc)
{
  std::stringstream ss;
  for (int line = loc.begin.line; line <= loc.end.line; line++) {
    auto &srcline = lines_[line - 1];
    if (line == loc.begin.line && line == loc.end.line) {
      ss << srcline.substr(loc.begin.column - 1,
                           loc.end.column - loc.begin.column);
    } else if (line == loc.begin.line) {
      ss << srcline.substr(loc.begin.column - 1);
    } else if (line < loc.end.line - 1) {
      ss << srcline;
    } else {
      ss << srcline.substr(0, loc.end.column - 1);
    }
  }
  return ss.str();
}

std::vector<MetaMap::Variant> MetaMap::associated(const Node &node)
{
  // See build_meta_map. We search only based on the start position.
  SourceLocation::Position loc = node.loc->current.begin;
  auto it = map_.find(loc);
  if (it == map_.end()) {
    return {};
  }
  auto result = std::move(it->second);
  map_.erase(it);
  return result;
}

std::vector<MetaMap::Variant> MetaMap::within(const Node &node)
{
  const auto &node_begin = node.loc->current.begin;
  const auto &node_end = node.loc->current.end;

  // We need to scan the full map and collection everything within
  // this node. Should only be done for full blocks, etc.
  std::vector<MetaMap::Variant> result;
  std::vector<SourceLocation::Position> to_erase;
  for (auto &[pos, entries] : map_) {
    if (pos.line >= node_begin.line &&
        (pos.line > node_begin.line || pos.column >= node_begin.column) &&
        pos.line <= node_end.line &&
        (pos.line < node_end.line || pos.column <= node_end.column)) {
      for (auto &entry : entries) {
        result.emplace_back(entry);
      }
      to_erase.emplace_back(pos);
    }
    if (pos.line > node_end.line) {
      break; // Early break, nothing else will match.
    }
  }

  // Remove all the entries we have cleared above.
  for (const auto &pos : to_erase) {
    map_.erase(map_.find(pos));
  }

  return result;
}

bool MetaMap::has_within(const Node &node) const
{
  const auto &node_begin = node.loc->current.begin;
  const auto &node_end = node.loc->current.end;

  for (const auto &[pos, entries] : map_) {
    if (pos.line >= node_begin.line &&
        (pos.line > node_begin.line || pos.column >= node_begin.column) &&
        pos.line <= node_end.line &&
        (pos.line < node_end.line || pos.column <= node_end.column)) {
      return true;
    }
    if (pos.line > node_end.line) {
      return false; // Past matching.
    }
  }

  return false;
}

ASTContext::ASTContext(std::string &&filename, std::string &&contents)
    : state_(std::make_unique<State>()),
      source_(
          std::make_shared<ASTSource>(std::move(filename), std::move(contents)))
{
}

ASTContext::ASTContext(const std::string &filename, const std::string &contents)
    : ASTContext(std::string(filename), std::string(contents))
{
}

ASTContext::ASTContext() : ASTContext("", "")
{
}

void ASTContext::clear()
{
  root = nullptr;
  state_->nodes_.clear();
  state_->diagnostics_->clear();
}

ASTContext::State::State() : diagnostics_(std::make_unique<Diagnostics>())
{
}

MetaMap ASTContext::build_meta_map() const
{
  // Build a location index for all nodes.
  std::map<SourceLocation, const Node *> loc_map;
  for (const auto &node : state_->nodes_) {
    loc_map[node->loc->current] = node.get();
  }

  // Now, for each piece of metadata, find the closest node.
  MetaMap result;
  for (auto &[meta_loc, spacing] : state_->metadata_) {
    auto it = loc_map.lower_bound(meta_loc);
    SourceLocation::Position dest;
    if (it == loc_map.end()) {
      // This is a trailing comment? Okay, just dump it without
      // anything associated.
      dest = meta_loc.begin;
    } else {
      dest = it->first.begin;
    }

    // Associated with the specific node location, and aggregate
    // all of the comments and spacing information. We store only
    // the beginning because it is possible that during printing
    // this will be picked up by different kinds.
    auto &vec = result.map_[dest];
    if (spacing > 0) {
      vec.emplace_back(static_cast<size_t>(spacing));
    } else {
      vec.emplace_back(source_->read(meta_loc));
    }
  }

  // We have our meta map.
  return result;
}

} // namespace bpftrace::ast
