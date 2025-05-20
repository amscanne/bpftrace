#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "ast/context.h"
#include "ast/pass_manager.h"

namespace bpftrace::ast {

class Node;

class Bitcode {
public:
  Bitcode(Node &node, const std::string &data) : node(node), data(data) {};

  // This is a reference to the original node that imported this, so
  // that a useful error can be generated somewhere.
  Node &node;

  // This is only loaded from the standard library, so it is always a
  // reference. This can be parsed and loaded in a subsequent pass.
  const std::string &data;
};

class ExternalObject {
public:
  ExternalObject(Node &node, std::filesystem::path path)
      : node(node), path(std::move(path)) {};

  // Per bitcode, this is a reference to the object.
  Node &node;

  // Objects are left on the filesystem, since these paths are passed directly
  // to the linker.
  std::filesystem::path path;
};

// Imports holds the set of imported modules. This includes the parsed ASTs for
// any source files, the loaded module for serialized modules, any dlhandles
// for loaded dynamic plugins, and the BPF objects for any binary blobs.
class Imports : public ast::State<"imports"> {
public:
  std::map<std::string, Bitcode> bitcode;
  std::map<std::string, ExternalObject> objects;
  std::map<std::string, ASTContext> scripts;
};

Pass CreateResolveImportsPass(std::vector<std::string> &&import_paths);

} // namespace bpftrace::ast
