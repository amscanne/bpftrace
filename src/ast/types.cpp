#include <optional>

#include "ast/ast.h"
#include "ast/visitor.h"
#include "btf/btf.h"
#include "btf/compat.h"
#include "struct.h"
#include "types.h"

namespace bpftrace::ast {

namespace {
// For now, the TypeBuilder is produces SizedType objects. These SizedType
// objects will be subsequently converted *back* to native BTF types using
// src/btf/compat.cpp.
//
// In the future, we can eliminate the full layer of SizedType, and just convert
// to BTF directly here from the spec. With this in place, we are effectively
// two complex conversion in two directions. Both these directions will soon
// be eliminated in favor of a native internal BTF type.
class TypeBuilder : public Visitor<TypeBuilder, std::optional<SizedType>> {
public:
  TypeBuilder(btf::Types &types) : types_(types) {};

  using Visitor<TypeBuilder, std::optional<SizedType>>::visit;
  std::optional<SizedType> visit(NamedType &named)
  {
    // Check if this an externally defined type. Note that
    // the type could be arbitrarily complex, so we are still
    // relying on the compat layer to do heavy lifting for us.
    auto extern_type = types_.lookup<btf::Typedef>(named.name);
    if (extern_type) {
      auto result = btf::getCompatType(extern_type);
      if (result) {
        return std::move(*result);
      }
    }

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
      return std::nullopt;
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
  std::optional<Struct> visitFields(std::vector<FieldDecl *> fields,
                                    bool is_union)
  {
    Struct result(0);
    ssize_t offset = 0;
    ssize_t struct_align = 1;

    for (auto &field : fields) {
      auto type = visit(field->type);
      if (!type) {
        return std::nullopt;
      }
      if (field->bitfield_width && !type->IsIntegerTy()) {
        return std::nullopt;
      }

      auto align = type->GetInTupleAlignment();
      struct_align = std::max(align, struct_align);
      auto size = static_cast<ssize_t>(type->GetSize());

      // For unions, all fields are at offset 0.
      //
      // For structs, fields are laid out sequentially with proper alignment.
      ssize_t field_offset = 0;
      if (!is_union) {
        auto padding = (align - (offset % align)) % align;
        if (padding)
          result.padded = true;
        offset += padding;
        field_offset = offset;
        offset += size;
      }

      std::optional<Bitfield> bitfield;
      if (field->bitfield_width) {
        // Calculate the bit offset within the field.
        //
        // For anonymous structs/unions, we compute the bitfield based on
        // the field's position within its containing integer type.
        bitfield = Bitfield(0, *field->bitfield_width);
      }

      result.AddField(field->name, *type, field_offset, bitfield);

      // For unions, track the maximum size.
      if (is_union && size > result.size) {
        result.size = size;
      }
    }

    // For structs, apply final padding and set size.
    if (!is_union) {
      auto padding = (struct_align - (offset % struct_align)) % struct_align;
      result.size = offset + padding;
    }
    result.align = struct_align;

    return result;
  }
  std::optional<SizedType> visit(StructType &struct_type)
  {
    if (std::holds_alternative<std::string>(struct_type.detail)) {
      auto name = std::get<std::string>(struct_type.detail);
      auto result = types_.lookup<btf::Struct>("struct " + name);
      if (result) {
        auto ok = btf::getCompatType(result);
        if (ok) {
          return *ok;
        }
      }
      return ident_to_sized_type("struct " + name);
    } else {
      // Build the type inline, based on the anonymous definition.
      auto &fields = std::get<std::vector<FieldDecl *>>(struct_type.detail);
      auto record = visitFields(fields, false);
      if (!record) {
        return std::nullopt;
      }
      auto shared = std::make_shared<Struct>(std::move(*record));
      return CreateRecord(std::move(shared));
    }
  }
  std::optional<SizedType> visit(UnionType &union_type)
  {
    if (std::holds_alternative<std::string>(union_type.detail)) {
      auto name = std::get<std::string>(union_type.detail);
      auto result = types_.lookup<btf::Union>("union " + name);
      if (result) {
        auto ok = btf::getCompatType(result);
        if (ok) {
          return *ok;
        }
      }
      return ident_to_sized_type("union " + name);
    } else {
      // Build the type inline, based on the anonymous definition.
      auto &fields = std::get<std::vector<FieldDecl *>>(union_type.detail);
      auto record = visitFields(fields, true);
      if (!record) {
        return std::nullopt;
      }
      auto shared = std::make_shared<Struct>(std::move(*record));
      return CreateRecord(std::move(shared));
    }
  }
  std::optional<SizedType> visit(EnumType &enum_type)
  {
    auto result = types_.lookup<btf::Enum>(enum_type.name);
    if (result) {
      auto ok = getCompatType(*result);
      if (ok) {
        return *ok;
      }
    }
    auto result64 = types_.lookup<btf::Enum64>(enum_type.name);
    if (result64) {
      auto ok = getCompatType(*result64);
      if (ok) {
        return *ok;
      }
    }
    return std::nullopt;
  }

private:
  btf::Types &types_;
};
} // namespace

SizedType TypeSpec::resolve(btf::Types &types)
{
  auto result = TypeBuilder(types).visit(*this);
  if (!result) {
    return CreateNone();
  }
  return std::move(*result);
}

} // namespace bpftrace::ast
