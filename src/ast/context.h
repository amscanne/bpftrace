#pragma once

#include <map>
#include <memory>
#include <variant>
#include <vector>

#include "ast/diagnostic.h"
#include "ast/pass_manager.h"

namespace bpftrace {

class Driver;

namespace ast {

class SourceLocation;
class Node;
class Program;

template <typename T>
concept NodeType = std::derived_from<T, Node>;

// Captures the original filename and source for a given AST.
//
// This is a heavy object, containing the full contents of the file. Only a
// single instance of this class should be created and referenced.
class ASTSource {
public:
  ASTSource(std::string &&filename, std::string &&input);
  ASTSource(const ASTSource &other) = delete;
  ASTSource &operator=(const ASTSource &other) = delete;

  const std::string filename;
  const std::string contents;

  // Reads the contents of the source corresponding to a specific location.
  std::string read(const SourceLocation &loc);

private:
  std::vector<std::string> lines_;

  friend class SourceLocation;
};

// MetaMap is an index of comments, etc.
//
// It lookups and removes comments associated with each node. It can be
// used to reconstruct the original source file, modulo any the intentional
// transformations (and basic comment syntax, etc.).
class MetaMap {
public:
  MetaMap() = default;
  MetaMap(const MetaMap &other) = delete;
  MetaMap &operator=(const MetaMap &other) = delete;
  MetaMap(MetaMap &&other) = default;
  MetaMap &operator=(MetaMap &&other) = default;

  // The Variant describes either comments (strings) or vspace (size_t).
  using Variant = std::variant<std::string, size_t>;

  // Associated will find comments that should be associated with this
  // node, and remove them from the map. Typically these are comments
  // that are immediately preceding the provided node.
  std::vector<Variant> associated(const Node &node);

  // This is a more complex operation; any remaining comments within the
  // scope of the node are returned. Typically this means comments that
  // might be trailing without a specific anchoring statement or expression.
  std::vector<Variant> within(const Node &node);

  // This is a variant of within which does not remain the metadata,
  // it merely checks whether some is contained in the boundaries.
  bool has_within(const Node &node) const;

private:
  std::map<SourceLocation::Position, std::vector<Variant>> map_;
  friend class ASTContext;
};

// Manages the lifetime of AST nodes.
//
// Nodes allocated by an ASTContext will be kept alive for the duration of the
// owning ASTContext object. The ASTContext also owns the canonical instance of
// the ASTSource, which is used by the Diagnostics to contextualize errors.
class ASTContext : public ast::State<"ast"> {
public:
  ASTContext(std::string &&filename, std::string &&contents);
  ASTContext(const std::string &filename, const std::string &contents);
  ASTContext();

  // Creates and returns a pointer to an AST node.
  template <NodeType T, typename... Args>
  constexpr T *make_node(Location &&loc, Args... args)
  {
    auto uniq_ptr = std::make_unique<T>(*this,
                                        std::move(loc),
                                        std::forward<Args>(args)...);
    auto *raw_ptr = uniq_ptr.get();
    state_->nodes_.push_back(std::move(uniq_ptr));
    return raw_ptr;
  }

  template <NodeType T, typename... Args>
  constexpr T *make_node(const SourceLocation &loc, Args &&...args)
  {
    return make_node<T, Args...>(std::make_shared<LocationChain>(loc),
                                 std::forward<Args>(args)...);
  }

  template <NodeType T, typename... Args>
  constexpr T *make_node(const Location &loc, Args... args)
  {
    return make_node<T, Args...>(Location(loc), std::forward<Args>(args)...);
  }

  template <NodeType T>
  constexpr T *clone_node(const Location &loc, const T *other)
  {
    if (other == nullptr) {
      return nullptr;
    }
    auto uniq_ptr = std::make_unique<T>(*this, loc, *other);
    auto *raw_ptr = uniq_ptr.get();
    state_->nodes_.push_back(std::move(uniq_ptr));
    return raw_ptr;
  }

  unsigned int node_count()
  {
    return state_->nodes_.size();
  }

  Diagnostics &diagnostics() const
  {
    return *state_->diagnostics_;
  }

  std::shared_ptr<ASTSource> source() const
  {
    return source_;
  }

  void add_comment(SourceLocation loc)
  {
    std::cerr << "ADD COMMENT " << loc << std::endl;
    state_->metadata_.emplace_back(std::move(loc), 0);
  }

  void add_vspace(SourceLocation loc, size_t elems)
  {
    std::cerr << "ADD VSPACE " << loc << std::endl;
    state_->metadata_.emplace_back(std::move(loc), elems);
  }

  // This function builds a comment map for the parsed AST. For every created
  // node, it provides a list of all the preceding (aka "owned") comments as
  // well as the vertical space.
  MetaMap build_meta_map() const;

  // clears all the nodes and diagnostics, but does not affect the underlying
  // `ASTSource` object. This is useful if you want to e.g. reparse the full
  // syntax tree in place.
  void clear();

  // Root points to a node in `state_.nodes_`.
  Program *root = nullptr;

private:
  // State owns the underlying nodes; they are permitted to take a reference to
  // this object since their lifetimes are bound.
  class State {
  public:
    State();
    std::vector<std::unique_ptr<Node>> nodes_;
    std::unique_ptr<Diagnostics> diagnostics_;
    std::vector<std::pair<SourceLocation, size_t>> metadata_;
  };

  std::unique_ptr<State> state_;
  std::shared_ptr<ASTSource> source_;

  friend class bpftrace::Driver;
  friend class Node;
};

} // namespace ast
} // namespace bpftrace
