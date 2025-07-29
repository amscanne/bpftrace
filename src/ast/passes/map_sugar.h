#pragma once

#include <unordered_map>

#include "ast/pass_manager.h"

namespace bpftrace::ast {

// MapMetadata contains metadata related to the sugared maps.
//
// This indicates whether the map is a scalar, and includes a list to the known
// key expressions and value expressions after desugaring.
class MapMetadata : public ast::State<"map-metadata"> {
public:
  struct Info {
    bool scalar;
    std::vector<Expression *> key_exprs;
    std::vector<Expression *> value_exprs;
  };
  std::unordered_map<std::string, bool> scalar;
  std::unordered_map<std::string, Expression *> key_types;
  std::unordered_map<std::string, Expression *> value_types;
};

Pass CreateMapSugarPass();
Pass CreateMapPercpuPass();

} // namespace bpftrace::ast
