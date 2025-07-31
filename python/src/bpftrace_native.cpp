/**
 * Native Python extension for bpftrace
 *
 * This module provides native C++ implementations for map operations
 * and integration with the bpftrace runtime.
 */

#include <memory>
#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "map_wrapper.h"

namespace py = pybind11;

/**
 * Native ArrayMap implementation that can interface with bpftrace maps
 */
class NativeArrayMap {
public:
  NativeArrayMap(size_t size, const std::string& name = "")
      : size_(size), name_(name.empty() ? generate_name() : name)
  {
    data_.resize(size_, 0);
  }

  void set_item(size_t key, int64_t value)
  {
    if (key >= size_) {
      throw std::out_of_range("Array index out of range");
    }
    data_[key] = value;
  }

  int64_t get_item(size_t key) const
  {
    if (key >= size_) {
      throw std::out_of_range("Array index out of range");
    }
    return data_[key];
  }

  int64_t get_item_with_default(size_t key, int64_t default_value = 0) const
  {
    if (key >= size_) {
      return default_value;
    }
    return data_[key];
  }

  size_t size() const
  {
    return size_;
  }
  const std::string& name() const
  {
    return name_;
  }

  std::string to_bpftrace_declaration() const
  {
    return "@" + name_ + "[int64] = int64;";
  }

  // Get all data for debugging/testing
  std::vector<int64_t> get_all_data() const
  {
    return data_;
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

size_t NativeArrayMap::counter_ = 0;

/**
 * Native HashMap implementation
 */
class NativeHashMap {
public:
  NativeHashMap(const std::string& name = "")
      : name_(name.empty() ? generate_name() : name)
  {
  }

  void set_item(const std::string& key, int64_t value)
  {
    data_[key] = value;
  }

  void set_item_int(int64_t key, int64_t value)
  {
    data_[std::to_string(key)] = value;
  }

  int64_t get_item(const std::string& key) const
  {
    auto it = data_.find(key);
    if (it == data_.end()) {
      return 0; // Default value
    }
    return it->second;
  }

  int64_t get_item_int(int64_t key) const
  {
    return get_item(std::to_string(key));
  }

  int64_t get_item_with_default(const std::string& key,
                                int64_t default_value = 0) const
  {
    auto it = data_.find(key);
    if (it == data_.end()) {
      return default_value;
    }
    return it->second;
  }

  const std::string& name() const
  {
    return name_;
  }

  std::string to_bpftrace_declaration() const
  {
    return "@" + name_ + "[int64] = int64;";
  }

  // Get all data for debugging/testing
  std::unordered_map<std::string, int64_t> get_all_data() const
  {
    return data_;
  }

  size_t size() const
  {
    return data_.size();
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

size_t NativeHashMap::counter_ = 0;

/**
 * BpftraceRunner - manages the execution of bpftrace scripts
 */
class BpftraceRunner {
public:
  BpftraceRunner() = default;

  void add_script(const std::string& script)
  {
    scripts_.push_back(script);
  }

  std::string generate_full_script() const
  {
    std::string full_script = "#!/usr/bin/env bpftrace\n\n";

    // Add map declarations
    for (const auto& decl : map_declarations_) {
      full_script += decl + "\n";
    }

    if (!map_declarations_.empty()) {
      full_script += "\n";
    }

    // Add all probe scripts
    for (const auto& script : scripts_) {
      full_script += script + "\n\n";
    }

    // Add END block
    full_script += "END\n{\n    // Script ended\n}\n";

    return full_script;
  }

  void register_map_declaration(const std::string& declaration)
  {
    map_declarations_.push_back(declaration);
  }

  void clear()
  {
    scripts_.clear();
    map_declarations_.clear();
  }

  size_t script_count() const
  {
    return scripts_.size();
  }

private:
  std::vector<std::string> scripts_;
  std::vector<std::string> map_declarations_;
};

/**
 * Utility functions for the transpiler
 */
class TranspilerUtils {
public:
  static std::string escape_string(const std::string& str)
  {
    std::string escaped;
    for (char c : str) {
      switch (c) {
        case '\n':
          escaped += "\\n";
          break;
        case '\t':
          escaped += "\\t";
          break;
        case '\r':
          escaped += "\\r";
          break;
        case '\\':
          escaped += "\\\\";
          break;
        case '"':
          escaped += "\\\"";
          break;
        default:
          escaped += c;
          break;
      }
    }
    return escaped;
  }

  static std::string format_bpftrace_printf(
      const std::string& format,
      const std::vector<std::string>& args)
  {
    std::string result = "printf(\"" + escape_string(format) + "\"";
    for (const auto& arg : args) {
      result += ", " + arg;
    }
    result += ");";
    return result;
  }

  static bool is_valid_identifier(const std::string& name)
  {
    if (name.empty() || !std::isalpha(name[0]) && name[0] != '_') {
      return false;
    }

    for (size_t i = 1; i < name.size(); ++i) {
      if (!std::isalnum(name[i]) && name[i] != '_') {
        return false;
      }
    }

    return true;
  }
};

// Global runner instance
static BpftraceRunner g_runner;

PYBIND11_MODULE(_bpftrace_native, m)
{
  m.doc() = "Native bpftrace Python bindings";

// Version info
#ifdef VERSION_INFO
  m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
  m.attr("__version__") = "dev";
#endif

  // NativeArrayMap class
  py::class_<NativeArrayMap>(m, "NativeArrayMap")
      .def(py::init<size_t, const std::string&>(),
           py::arg("size"),
           py::arg("name") = "")
      .def("__setitem__", &NativeArrayMap::set_item)
      .def("__getitem__", &NativeArrayMap::get_item)
      .def("get",
           &NativeArrayMap::get_item_with_default,
           py::arg("key"),
           py::arg("default") = 0)
      .def("size", &NativeArrayMap::size)
      .def("name", &NativeArrayMap::name)
      .def("to_bpftrace_declaration", &NativeArrayMap::to_bpftrace_declaration)
      .def("get_all_data", &NativeArrayMap::get_all_data)
      .def("__len__", &NativeArrayMap::size);

  // NativeHashMap class
  py::class_<NativeHashMap>(m, "NativeHashMap")
      .def(py::init<const std::string&>(), py::arg("name") = "")
      .def("__setitem__",
           py::overload_cast<const std::string&, int64_t>(
               &NativeHashMap::set_item))
      .def("__setitem__",
           py::overload_cast<int64_t, int64_t>(&NativeHashMap::set_item_int))
      .def("__getitem__",
           py::overload_cast<const std::string&>(&NativeHashMap::get_item,
                                                 py::const_))
      .def("__getitem__",
           py::overload_cast<int64_t>(&NativeHashMap::get_item_int, py::const_))
      .def("get",
           &NativeHashMap::get_item_with_default,
           py::arg("key"),
           py::arg("default") = 0)
      .def("name", &NativeHashMap::name)
      .def("to_bpftrace_declaration", &NativeHashMap::to_bpftrace_declaration)
      .def("get_all_data", &NativeHashMap::get_all_data)
      .def("size", &NativeHashMap::size)
      .def("__len__", &NativeHashMap::size);

  // BpftraceRunner class
  py::class_<BpftraceRunner>(m, "BpftraceRunner")
      .def(py::init<>())
      .def("add_script", &BpftraceRunner::add_script)
      .def("generate_full_script", &BpftraceRunner::generate_full_script)
      .def("register_map_declaration",
           &BpftraceRunner::register_map_declaration)
      .def("clear", &BpftraceRunner::clear)
      .def("script_count", &BpftraceRunner::script_count);

  // TranspilerUtils class
  py::class_<TranspilerUtils>(m, "TranspilerUtils")
      .def_static("escape_string", &TranspilerUtils::escape_string)
      .def_static("format_bpftrace_printf",
                  &TranspilerUtils::format_bpftrace_printf)
      .def_static("is_valid_identifier", &TranspilerUtils::is_valid_identifier);

  // Global runner instance
  m.def(
      "get_global_runner",
      []() -> BpftraceRunner& { return g_runner; },
      py::return_value_policy::reference);

  // Utility functions
  m.def("reset_counters", []() {
    NativeArrayMap::counter_ = 0;
    NativeHashMap::counter_ = 0;
  });
}
