/**
 * Map wrapper implementation for bpftrace Python bindings
 */

#include "map_wrapper.h"
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace bpftrace {
namespace python {

/**
 * Concrete ArrayMap implementation
 */
class ArrayMapImpl : public ArrayMapWrapper {
public:
  ArrayMapImpl(size_t size, const std::string& name)
      : size_(size), name_(name.empty() ? generate_name() : name)
  {
    data_.resize(size_, 0);
  }

  std::string name() const override
  {
    return name_;
  }

  std::string to_bpftrace_declaration() const override
  {
    return "@" + name_ + "[int64] = int64;";
  }

  size_t size() const override
  {
    return size_;
  }

  void set_item(size_t key, int64_t value) override
  {
    if (key >= size_) {
      throw std::out_of_range("Array index out of range");
    }
    data_[key] = value;
  }

  int64_t get_item(size_t key) const override
  {
    if (key >= size_) {
      throw std::out_of_range("Array index out of range");
    }
    return data_[key];
  }

  int64_t get_item_with_default(size_t key,
                                int64_t default_value) const override
  {
    if (key >= size_) {
      return default_value;
    }
    return data_[key];
  }

private:
  size_t size_;
  std::string name_;
  std::vector<int64_t> data_;
  static size_t counter_;

  static std::string generate_name()
  {
    return "array_" + std::to_string(counter_++);
  }
};

size_t ArrayMapImpl::counter_ = 0;

/**
 * Concrete HashMap implementation
 */
class HashMapImpl : public HashMapWrapper {
public:
  HashMapImpl(const std::string& name)
      : name_(name.empty() ? generate_name() : name)
  {
  }

  std::string name() const override
  {
    return name_;
  }

  std::string to_bpftrace_declaration() const override
  {
    return "@" + name_ + "[int64] = int64;";
  }

  size_t size() const override
  {
    return data_.size();
  }

  void set_item(const std::string& key, int64_t value) override
  {
    data_[key] = value;
  }

  void set_item_int(int64_t key, int64_t value) override
  {
    data_[std::to_string(key)] = value;
  }

  int64_t get_item(const std::string& key) const override
  {
    auto it = data_.find(key);
    return (it != data_.end()) ? it->second : 0;
  }

  int64_t get_item_int(int64_t key) const override
  {
    return get_item(std::to_string(key));
  }

  int64_t get_item_with_default(const std::string& key,
                                int64_t default_value) const override
  {
    auto it = data_.find(key);
    return (it != data_.end()) ? it->second : default_value;
  }

private:
  std::string name_;
  std::unordered_map<std::string, int64_t> data_;
  static size_t counter_;

  static std::string generate_name()
  {
    return "hash_" + std::to_string(counter_++);
  }
};

size_t HashMapImpl::counter_ = 0;

// Factory functions
std::unique_ptr<ArrayMapWrapper> create_array_map(size_t size,
                                                  const std::string& name)
{
  return std::make_unique<ArrayMapImpl>(size, name);
}

std::unique_ptr<HashMapWrapper> create_hash_map(const std::string& name)
{
  return std::make_unique<HashMapImpl>(name);
}

} // namespace python
} // namespace bpftrace
