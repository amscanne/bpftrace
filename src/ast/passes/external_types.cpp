#include <sstream>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/external_types.h"
#include "ast/passes/printer.h"
#include "ast/visitor.h"
#include "driver.h"

namespace bpftrace::ast {

char TypesError::ID;

void TypesError::log(llvm::raw_ostream &OS) const
{
  OS << message_;
}

namespace {

class CastResolver : public Visitor<CastResolver, std::optional<SizedType>> {
public:
  CastResolver(ASTContext &ast) : ast_(ast) {};

  using Visitor<CastResolver, std::optional<SizedType>>::visit;

  std::optional<SizedType> visit(NamedType &named)
  {
    // This takes the previous type_spec logic from the parser
    // and evaluates it locally. In the future, this will actually
    // parse the type from BTF. But this is a temporary measure.
    if (named.name == "void") {
      return CreateVoid();
    } else if (named.name == "bool") {
      return CreateBool();
    } else if (named.name == "char") {
      return CreateInt8();
    } else if (named.name == "int8") {
      return CreateInt8();
    } else if (named.name == "int16") {
      return CreateInt16();
    } else if (named.name == "int32") {
      return CreateInt32();
    } else if (named.name == "int64") {
      return CreateInt64();
    } else if (named.name == "uint8") {
      return CreateUInt8();
    } else if (named.name == "uint16") {
      return CreateUInt16();
    } else if (named.name == "uint32") {
      return CreateUInt32();
    } else if (named.name == "uint64") {
      return CreateUInt64();
    } else if (named.name == "inet") {
      return CreateInet(0);
    } else if (named.name == "buffer") {
      return CreateBuffer(0);
    } else if (named.name == "string") {
      return CreateString(0);
    } else if (named.name == "min_t") {
      return CreateMin(true);
    } else if (named.name == "max_t") {
      return CreateMax(true);
    } else if (named.name == "count_t") {
      return CreateCount();
    } else if (named.name == "sum_t") {
      return CreateSum(true);
    } else if (named.name == "avg_t") {
      return CreateAvg(true);
    } else if (named.name == "stats_t") {
      return CreateStats(true);
    } else if (named.name == "umin_t") {
      return CreateMin(false);
    } else if (named.name == "umax_t") {
      return CreateMax(false);
    } else if (named.name == "usum_t") {
      return CreateSum(false);
    } else if (named.name == "uavg_t") {
      return CreateAvg(false);
    } else if (named.name == "ustats_t") {
      return CreateStats(false);
    } else if (named.name == "timestamp") {
      return CreateTimestamp();
    } else if (named.name == "macaddr_t") {
      return CreateMacAddress();
    } else if (named.name == "cgroup_path_t") {
      return CreateCgroupPath();
    } else {
      return ident_to_record(named.name, 0);
    }
  }
  std::optional<SizedType> visit(TypeSpec &spec)
  {
    return visit(spec.value);
  }
  std::optional<SizedType> visit(PointerType &ptr)
  {
    if (auto elem = visit(ptr.pointee)) {
      return CreatePointer(*elem);
    }
    return std::nullopt;
  }
  std::optional<SizedType> visit(ArrayType &arr)
  {
    if (auto *named = arr.element_type.as<NamedType>()) {
      if (named->name == "inet") {
        return CreateInet(arr.size);
      } else if (named->name == "buffer") {
        return CreateBuffer(arr.size);
      } else if (named->name == "string") {
        return CreateString(arr.size);
      }
    }
    if (auto elem = visit(arr.element_type)) {
      return CreateArray(arr.size, *elem);
    }
    return std::nullopt;
  }
  std::optional<SizedType> visit(StructType &struct_type)
  {
    if (std::holds_alternative<std::string>(struct_type.detail)) {
      return ident_to_sized_type("struct " +
                                 std::get<std::string>(struct_type.detail));
    }
    return std::nullopt;
  }
  std::optional<SizedType> visit(UnionType &union_type)
  {
    if (std::holds_alternative<std::string>(union_type.detail)) {
      return ident_to_sized_type("union " +
                                 std::get<std::string>(union_type.detail));
    }
    return std::nullopt;
  }
  std::optional<SizedType> visit(EnumType &enum_type)
  {
    return ident_to_sized_type(enum_type.name);
  }
  std::optional<SizedType> visit(Expression &expr)
  {
    if (auto *cast_or_binop = expr.as<CastOrBinop>()) {
      // Attempt to resolve the printer expression as a type. If it
      // resolves correctly, then this is a *cast*.
      //
      // First, we need to convert the expression to a naked string.
      std::stringstream ss;
      MetadataIndex metadata;
      ss << Formatter(FormatMode::Minimal, metadata, 120)
                .visit(cast_or_binop->lhs);
      // Next, we attempt to parse this as a type.
      ASTContext single_type("type", ss.str());
      Driver driver(single_type);
      auto type_spec = driver.parse_type();
      if (type_spec) {
        // The spec itself is valid, but we also require the underlying
        // type to be valid. For example, "foo" is a valid spec on its own,
        // but will often be wrong; we also require a valid type resolution.
        auto sized_type = visit(*type_spec);
        if (sized_type) {
          auto *unop = ast_.make_node<Unop>(cast_or_binop->loc,
                                            cast_or_binop->op,
                                            cast_or_binop->rhs);
          expr.value = ast_.make_node<Cast>(cast_or_binop->loc,
                                            *type_spec,
                                            unop);
          return std::nullopt; // Converted to a cast.
        }
      }
      // Convert to a binary expression.
      expr.value = ast_.make_node<Binop>(cast_or_binop->loc,
                                         cast_or_binop->op,
                                         cast_or_binop->lhs,
                                         cast_or_binop->rhs);
    }
  }

private:
  ASTContext &ast_;
};

} // namespace

ast::Pass CreateDefineExternalTypesPass()
{
  return ast::Pass::create("ExternalTypes",
                           [](ASTContext &ast) -> Result<ExternalTypes> {
                             CastResolver(ast).visit(ast.root);
                           });
}

} // namespace bpftrace::ast
