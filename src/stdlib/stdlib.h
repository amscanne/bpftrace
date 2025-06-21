#pragma once

#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>

#include "util/type_name.h"

namespace bpftrace::stdlib {

// Value is the in-memory representation of a type. For simplicity, this
// will always be the raw bits. These are either copied on initialization
// or, if it fits within a native pointer, stored inline.
class Value {
public:
  Value(void *ptr, size_t n)
  {
    if (n <= sizeof(uintptr_t)) {
      uintptr_t v = 0;
      memcpy(&v, ptr, n);
      data_ = v;
    } else {
      void *data = malloc(n);
      if (data == nullptr) {
        throw std::bad_alloc();
      }
      memcpy(data, ptr, n);
      data_ = data;
    }
  }
  ~Value()
  {
    if (std::holds_alternative<void *>(data_)) {
      // Free the memory if it was allocated.
      free(std::get<void *>(data_));
    }
  }
  template <typename T>
  T &data()
  {
    if (std::holds_alternative<void *>(data_)) {
      // Return a reference to the stored pointer.
      return *reinterpret_cast<T *>(std::get<void *>(data_));
    } else {
      // Return a reference to the internal bits.
      const auto &v = std::get<uintptr_t>(data_);
      return *reinterpret_cast<T *>(&v);
    }
  }
  template <typename T>
  const T &data() const
  {
    // Same as above, but const-safe version.
    if (std::holds_alternative<void *>(data_)) {
      return *reinterpret_cast<const T *>(std::get<void *>(data_));
    } else {
      const auto &v = std::get<uintptr_t>(data_);
      return *reinterpret_cast<const T *>(&v);
    }
  }

private:
  std::variant<uintptr_t, void *> data_;
};

class TypeInfo {
public:
  // When a value is no longer used, the `bpf_free` method will be called
  // to release the value in BPF. This is used for defining types that have
  // a lifecycle (e.g. need to have references released, etc.).
  //
  // This has the prototype:
  //  bpf_free(T *data);
  static std::optional<std::string> bpf_free()
  {
    return std::nullopt;
  }

  // If the `bpf_aggregate` method is provided, then per-CPU map variants
  // will be preferred and reads will aggregate using this method. If such
  // a method is provided, then `host_aggregate` must also be provided.
  //
  // This has the prototype:
  //  bpf_aggregate(T *dst, T *src);
  static std::optional<std::string> bpf_aggregate()
  {
    return std::nullopt;
  }

  // Aggregates two values on the host side.
  virtual void aggregate([[maybe_unused]] Value &dst,
                         [[maybe_unused]] const Value &src) const
  {
  }

  // The format method is used to format the type for printing. A fixed set
  // of outputs are supported, which will be serialized based on the internal
  // output (e.g. text, json, etc.).
  //
  // This must be provided for all types.
  using OutputVariant =
      std::variant<int64_t, uint64_t, double, std::string, bool>;
  virtual OutputVariant format(const Value &val) const;

  // When an object is no longer used on the host-side, the `free` method will
  // be called to release any associated memory (e.g. in side maps, etc.).
  virtual void free([[maybe_unused]] const Value &val) const {};
};

class TypeInfoFactory {
public:
  // Called to create the concrete `TypeInfo` object. This allows the
  // `TypeInfo` to bind with the specific `bpf_object`, lookup and memoize
  // maps, etc. Many types will not need this.
  virtual std::unique_ptr<TypeInfo> create(struct bpf_object *obj) = 0;

  // See above, these wrap the TypeInfo methods.
  virtual std::optional<std::string> bpf_free() const = 0;
  virtual std::optional<std::string> bpf_aggregate() const = 0;
};

class Stdlib {
public:
  // files is the set of files embedded in the standard library.
  //
  // This is constructed automatically from a generated `stdlib.cpp`.
  static const std::map<std::string, std::string_view> files;

  // type_factories are the set of types defined in the standard library.
  //
  // These are dynamically registered.
  static std::map<std::string, TypeInfoFactory &> type_factories;
};

// TypeImpl is used to implement the TypeInfo interface for a given type.
//
// With a class defined, you should instantiate a static factory for each
// type. This will have the form:
//
//   static MyType::Factory _;
template <util::TypeName T>
class TypeImpl : public TypeInfo {
public:
  class Factory : public TypeInfoFactory {
  public:
    Factory()
    {
      Stdlib::type_factories[T.str()] = *this;
    }
    std::unique_ptr<TypeInfo> create(struct bpf_object *obj) override
    {
      return std::make_unique<TypeImpl<T>>(obj);
    }
    std::optional<std::string> bpf_free() const override
    {
      return TypeImpl<T>::bpf_free();
    }
    std::optional<std::string> bpf_aggregate() const override
    {
      return TypeImpl<T>::bpf_aggregate();
    }
  };
};

} // namespace bpftrace::stdlib
