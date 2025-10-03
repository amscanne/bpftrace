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
  for (int line = loc.begin.line - 1; line <= loc.end.line - 1; line++) {
    auto &srcline = lines_[line];
    if (line == loc.begin.line && line == loc.end.line) {
      ss << srcline.substr(loc.begin.column - 1,
                           loc.end.column - loc.begin.column);
    } else if (line == loc.begin.line) {
      ss << srcline.substr(loc.begin.column - 1);
    } else if (line < loc.end.line - 1) {
      ss << srcline;
    } else {
      ss << srcline.substr(0, loc.end.column);
    }
  }
  return ss.str();
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

ASTContext::MetaMap ASTContext::build_meta_map() const
{
  // Build a location index for all nodes.
  std::map<SourceLocation, const Node *> loc_map;
  for (const auto &node : state_->nodes_) {
    // This overrides any existing nodes with identical locations with later
    // nodes. The later nodes are likely to be the ones used by any
    // transformations, etc. and therefore the ones to get printed.
    loc_map[node->loc->current] = node.get();
  }

  // Now, for each piece of metadata, find the closest node. This relies on the
  // comparison operators for SourceLocation, which indicates that larger
  // entries come *first* in the node hierarchy, when their beginning locations
  // are matching. This allows for the comment and space to be associated with
  // the largest logical component in the AST, as is the likely intention.
  MetaMap result;
  for (auto &[meta_loc, meta_type] : state_->metadata_) {
    auto it = loc_map.upper_bound(meta_loc);
    if (it == loc_map.end()) {
      // This is a trailing comment? Weird. We lose this.
      continue;
    }
    auto &vec = result[it->second];
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
