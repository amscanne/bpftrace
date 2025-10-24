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

std::vector<MetaMap::Variant> MetaMap::pop(const Node &node)
{
  // See build_meta_map. We zonk the end line and column for that index.
  // This allows us to match nodes against the location of the metadata,
  // rather than requiring a very strict association with the node.
  SourceLocation loc = node.loc->current;
  loc.end.line = 0;
  loc.end.column = 0;

  // Once matched, the metadata is removed.
  auto it = map_.find(loc);
  if (it == map_.end()) {
    return {};
  }
  auto result = std::move(it->second);
  map_.erase(it);
  return result;
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

    std::cerr << "ALL LOCS: " << typeid(*(node.get())).name() << " @ "
              << node->loc->current.begin.line << ":"
              << node->loc->current.begin.column << std::endl;
  }

  // Now, for each piece of metadata, find the closest node.
  MetaMap result;
  for (auto &[meta_loc, meta_type] : state_->metadata_) {
    auto it = loc_map.upper_bound(meta_loc);
    if (it == loc_map.end()) {
      // This is a trailing comment? Weird. We lose this.
      continue;
    }

    std::cerr << "MAP: " << meta_loc.begin.line << ":" << meta_loc.begin.column
              << " => " << typeid(*(it->second)).name() << " @ "
              << it->second->loc->current.begin.line << ":"
              << it->second->loc->current.begin.column << std::endl;

    // The result map uses zonked end columns; see above.
    auto loc = it->first;
    loc.end.line = 0;
    loc.end.column = 0;
    auto &vec = result.map_[loc];
    switch (meta_type) {
      case VerticalSpace:
        vec.emplace_back(
            static_cast<size_t>(meta_loc.end.column - meta_loc.begin.column));
        break;
      case Comment:
        vec.emplace_back(source_->read(meta_loc));
        break;
    }
  }

  // We have our meta map.
  return result;
}

} // namespace bpftrace::ast
