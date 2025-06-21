#pragma once

#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>

#include "bpfbytecode.h"
#include "output/output.h"
#include "util/opaque.h"
#include "util/type_name.h"

namespace bpftrace::stdlib {

class TypeInfo {
public:
  // Returns the type name.
  //
  // Note that this must be the `typedef` name, and should resolve in the
  // global types to the type in question.
  virtual std::string name() const = 0;

  // When a value is no longer used, the `bpf_free` method will be called
  // to release the value in BPF. This is used for defining types that have
  // a lifecycle (e.g. need to have references released, etc.).
  //
  // This has the prototype:
  //  bpf_free(T *data);
  virtual std::optional<std::string> bpf_free() const
  {
    return std::nullopt;
  }

  // If the `bpf_aggregate` method is provided, then per-CPU map variants
  // will be preferred and reads will aggregate using this method. If such
  // a method is provided, then `host_aggregate` must also be provided.
  //
  // This has the prototype:
  //  bpf_aggregate(T *dst, T *src);
  virtual std::optional<std::string> bpf_aggregate() const
  {
    return std::nullopt;
  }

  // Aggregates two values on the host side. This will be called iff the
  // `bpf_aggregate` method is called, which indicates that a per-CPU variant
  // will be used for maps, etc.
  virtual void aggregate([[maybe_unused]] OpaqueValue &dst,
                         [[maybe_unused]] const OpaqueValue &src) const
  {
  }

  // The format method is used to format the type for printing.
  //
  // This must be provided for all types.
  virtual output::Primitive format(const OpaqueValue &value) const;

  // When an object is no longer used on the host-side, the `free` method will
  // be called to release any associated memory (e.g. in side maps, etc.).
  virtual void free([[maybe_unused]] const OpaqueValue &value) const
  {
  }
};

// TypeFactory is used to bind a type name to a given BpfBytecode instance.
//
// This is effectively a single function that allows to create a type instance
// bound to the specific instance.
class TypeFactory {
public:
  virtual std::unique_ptr<TypeInfo> create(
      const BpfBytecode &bytecode) const = 0;
};

// Stdlib is the static class that holds registered files and types.
class Stdlib {
public:
  // files is the set of files embedded in the standard library.
  //
  // This is constructed automatically from a generated `stdlib.cpp`.
  static const std::map<std::string, std::string_view> files;

  // types is the set of type factories defined in the standard library.
  //
  // These are dynamically registered.
  static std::map<std::string, TypeFactory *> type_factories;
};

// TypeImpl is used to implement the TypeInfo interface for a given type.
//
// With a class defined, you should instantiate a static factory for each
// type. This will have the form:
//
//   class MyType : TypeImpl<MyType, "my_type"> {};
//   static MyType::Factory _;
template <typename T, util::TypeName TN>
class TypeImpl : public TypeInfo {
public:
  TypeImpl(BpfBytecode &bytecode) : bytecode_(bytecode) {};

  std::string name() const override
  {
    return TN.str();
  }

  class Factory {
  public:
    Factory()
    {
      Stdlib::type_factories[TN.str()] = this;
    }
    std::unique_ptr<TypeInfo> create(BpfBytecode &bytecode) const override
    {
      return std::make_unique<T>(bytecode);
    }
  };

protected:
  BpfBytecode &bytecode_;
};

} // namespace bpftrace::stdlib
