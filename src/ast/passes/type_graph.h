#pragma once

#include <memory>

#include "ast/ast.h"
#include "ast/pass_manager.h"

namespace bpftrace::ast {

class TypeGraphDatabase;

// TypeGraph contains a representation of the type graph used for type
// inference.
//
// This must be used to resolve types found in individual AST nodes.
class TypeGraph : public ast::State<"type-graph"> {
public:
  SizedType get_type(Node &node);
  SizedType get_key_type(Map &map);
  SizedType get_value_type(Map &map);

private:
  std::unique_ptr<TypeGraphDatabase> db_;
};

Pass CreateTypeGraphPass();

} // namespace bpftrace::ast
