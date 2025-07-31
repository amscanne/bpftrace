/**
 * Map wrapper header for bpftrace Python bindings
 *
 * This header defines interfaces for wrapping bpftrace maps
 * for use in Python.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace bpftrace {
namespace python {

/**
 * Base class for map wrappers
 */
class MapWrapperBase {
public:
  virtual ~MapWrapperBase() = default;

  virtual std::string name() const = 0;
  virtual std::string to_bpftrace_declaration() const = 0;
  virtual size_t size() const = 0;
};

/**
 * Array map wrapper interface
 */
class ArrayMapWrapper : public MapWrapperBase {
public:
  virtual ~ArrayMapWrapper() = default;

  virtual void set_item(size_t key, int64_t value) = 0;
  virtual int64_t get_item(size_t key) const = 0;
  virtual int64_t get_item_with_default(size_t key,
                                        int64_t default_value) const = 0;
};

/**
 * Hash map wrapper interface
 */
class HashMapWrapper : public MapWrapperBase {
public:
  virtual ~HashMapWrapper() = default;

  virtual void set_item(const std::string& key, int64_t value) = 0;
  virtual void set_item_int(int64_t key, int64_t value) = 0;
  virtual int64_t get_item(const std::string& key) const = 0;
  virtual int64_t get_item_int(int64_t key) const = 0;
  virtual int64_t get_item_with_default(const std::string& key,
                                        int64_t default_value) const = 0;
};

/**
 * Factory functions for creating map wrappers
 */
std::unique_ptr<ArrayMapWrapper> create_array_map(size_t size,
                                                  const std::string& name = "");
std::unique_ptr<HashMapWrapper> create_hash_map(const std::string& name = "");

} // namespace python
} // namespace bpftrace
