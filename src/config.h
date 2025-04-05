#pragma once

#include <cstdint>
#include <map>
#include <variant>

#include "log.h"
#include "types.h"
#include "util/int_parser.h"
#include "util/result.h"

namespace bpftrace {

// Generic configuration error that wraps a string.
class ConfigError : public ErrorInfo<ConfigError> {
public:
  static char ID;
  ConfigError(std::string &&detail) : detail_(std::move(detail)) {};
  void log(llvm::raw_ostream &OS) const override
  {
    OS << detail_;
  }

private:
  std::string detail_;
};

// Specific key has been renamed, must be handled by caller.
class RenameError : public ErrorInfo<RenameError> {
public:
  static char ID;
  RenameError(std::string &&name) : name_(std::move(name)) {};
  void log(llvm::raw_ostream &OS) const override
  {
    OS << "key has been renamed to '" << name_ << "'";
  }

private:
  std::string name_;
};

enum class ConfigKey {
  cpp_demangle,
  lazy_symbolication,
  print_maps_on_exit,
  use_blazesym,
  unstable_map_decl,
  unstable_import,
  log_size,
  max_bpf_progs,
  max_cat_bytes,
  max_map_keys,
  max_probes,
  max_strlen,
  max_type_res_iterations,
  on_stack_limit,
  perf_rb_pages,
  license,
  str_trunc_trailer,
  missing_probes,
  stack_mode,
  user_symbol_cache_type,
  symbol_source,
  __sentinel__,
};

enum class ConfigMissingProbes {
  ignore,
  warn,
  error,
};

// If you want to be able to parse custom configuration, then simply
// provide a specialization of the `TypeSelector` class that specifies
// the storage type along with the implementation of the operators to
// parse any string inputs. All custom types must be convertible to the
// `uint64_t` type, since this is how they will be stored in the config.
template <ConfigKey K, typename enable = void>
struct ConfigParser {
  // The default key required.
  using type = uint64_t;
  using storage_type = uint64_t;
  Result<type> parse([[maybe_unused]] const type &old, const std::string &s)
  {
    // If this can be parsed as a literal integer, then we take that.
    try {
      return util::to_uint(s, 0);
    } catch (const std::exception &e) {
      return make_error<ConfigError>(std::string(e.what()));
    }
  }
  storage_type marshal(type val)
  {
    return static_cast<storage_type>(val);
  }
  type unmarshal(storage_type val)
  {
    return static_cast<type>(val);
  }
};

template <ConfigKey K>
struct ConfigParser<
    K,
    std::enable_if_t<
        K == ConfigKey::cpp_demangle || K == ConfigKey::lazy_symbolication ||
        K == ConfigKey::print_maps_on_exit || K == ConfigKey::unstable_import ||
        K == ConfigKey::unstable_map_decl || K == ConfigKey::use_blazesym>> {
  using type = bool;
  using storage_type = uint64_t;
  Result<type> parse([[maybe_unused]] const type &old, const std::string &s)
  {
    if (s == "1" || s == "true" || s == "TRUE" || s == "on" || s == "ON") {
      return true;
    } else if (s == "0" || s == "false" || s == "FALSE" || s == "off" ||
               s == "OFF") {
      return false;
    } else {
      return make_error<ConfigError>(
          "Invalid bool value: valid values are true, false, 1 or 0.");
    }
  }
  storage_type marshal(type val)
  {
    return static_cast<storage_type>(val);
  }
  type unmarshal(storage_type val)
  {
    return val != 0;
  }
};

template <ConfigKey K>
struct ConfigParser<K,
                    std::enable_if_t<K == ConfigKey::str_trunc_trailer ||
                                     K == ConfigKey::license>> {
  using type = std::string;
  using storage_type = std::string;
  storage_type marshal(type val)
  {
    return val;
  }
  type unmarshal(storage_type val)
  {
    return val;
  }
};

template <ConfigKey K>
struct ConfigParser<K,
                    std::enable_if_t<K == ConfigKey::user_symbol_cache_type>> {
  using type = UserSymbolCacheType;
  using storage_type = uint64_t;
  Result<type> parse([[maybe_unused]] const type &old, const std::string &s)
  {
    if (s == "1") {
      return old; // Leave as the default.
    } else if (s == "per_pid" || s == "PER_PID") {
      return UserSymbolCacheType::per_pid;
    } else if (s == "none" || s == "NONE" || s == "0") {
      return UserSymbolCacheType::none;
    } else {
      return make_error<ConfigError>(
          "Invalid value for cache_user_symbols: valid values are PER_PID, "
          "PER_PROGRAM, and NONE.");
    }
  }
  storage_type marshal(type val)
  {
    return static_cast<storage_type>(val);
  }
  type unmarshal(storage_type val)
  {
    return static_cast<type>(val);
  }
};

template <ConfigKey K>
struct ConfigParser<K, std::enable_if_t<K == ConfigKey::stack_mode>> {
  using type = StackMode;
  using storage_type = uint64_t;
  Result<type> parse([[maybe_unused]] const type &old, const std::string &s)
  {
    if (s == "bpftrace") {
      return StackMode::bpftrace;
    } else if (s == "raw") {
      return StackMode::raw;
    } else if (s == "perf") {
      return StackMode::perf;
    } else {
      return make_error<ConfigError>("Invalid value for stack_mode: valid "
                                     "values are bpftrace, raw and perf.");
    }
  }
  storage_type marshal(type val)
  {
    return static_cast<storage_type>(val);
  }
  type unmarshal(storage_type val)
  {
    return static_cast<type>(val);
  }
};

template <ConfigKey K>
struct ConfigParser<K, std::enable_if_t<K == ConfigKey::missing_probes>> {
  using type = ConfigMissingProbes;
  using storage_type = uint64_t;
  Result<type> parse([[maybe_unused]] const type &old, const std::string &s)
  {
    if (s == "ignore") {
      return ConfigMissingProbes::ignore;
    } else if (s == "warn") {
      return ConfigMissingProbes::warn;
    } else if (s == "error") {
      return ConfigMissingProbes::error;
    } else {
      return make_error<ConfigError>("Invalid value for missing_probes: valid "
                                     "values are ignore, warn, and error.");
    }
  }
  storage_type marshal(type val)
  {
    return static_cast<storage_type>(val);
  }
  type unmarshal(storage_type val)
  {
    return static_cast<type>(val);
  }
};

class Config {
public:
  explicit Config(bool has_cmd = false);

  bool is_unstable(const std::string &key);
  Result<OK> load_environment();

  // Finds the mapping from string to ConfigKey. May return a `RenameError`
  // that should be handled by the caller in an appropriate way.
  static Result<ConfigKey> lookup(const std::string &key);

  template <ConfigKey K>
  Result<typename ConfigParser<K>::type> get() const
  {
    using T = typename ConfigParser<K>::type;
    using S = typename ConfigParser<K>::storage_type;

    // The key must be valid.
    auto it = config_map_.find(K);
    if (it == config_map_.end()) {
      return make_error<ConfigError>("Config key does not exist in map");
    }

    // The storage type must be used.
    if (!std::holds_alternative<S>(it->second)) {
      return make_error<ConfigError>("Type mismatch for config key");
    }

    // Return as the native type.
    if constexpr (std::is_same_v<S, T>) {
      return std::get<S>(it->second);
    } else {
      ConfigParser<K> parser;
      return parser.unmarshal(std::get<S>(it->second));
    }
  }

  template <ConfigKey K>
  typename ConfigParser<K>::type must_get() const
  {
    auto v = get<K>();
    if (!v) {
      LOG(BUG) << v.takeError();
      __builtin_unreachable();
    } else {
      return std::move(*v);
    }
  }

  // Strings are the only way to completely dynamically set keys.
  Result<OK> set(const std::string &key, const std::string &value);
  Result<OK> set(const std::string &key, uint64_t value);

  // This may accept the native type for the key, or a string.
  template <ConfigKey K, typename U = typename ConfigParser<K>::type>
  Result<OK> set(U val)
    requires(std::is_same_v<std::decay_t<U>, typename ConfigParser<K>::type> ||
             std::is_same_v<std::decay_t<U>,
                            typename ConfigParser<K>::storage_type> ||
             std::is_same_v<std::decay_t<U>, std::string> ||
             std::is_same_v<U, const char *>)
  {
    using T = typename ConfigParser<K>::type;
    using S = typename ConfigParser<K>::storage_type;

    // Ensure that something is set.
    auto it = config_map_.find(K);
    if (it == config_map_.end()) {
      return make_error<ConfigError>("No default set for config key");
    }

    // Check for consistency.
    if (std::holds_alternative<S>(it->second)) {
      return make_error<ConfigError>("Type mismatch for config key");
    }

    // If the type is not the storage type, need to convert.
    if constexpr (std::is_same_v<S, std::decay_t<U>> ||
                  (std::is_same_v<S, std::string> &&
                   std::is_same_v<U, const char *>)) {
      it->second = val;
    } else if constexpr (std::is_same_v<T, std::decay_t<U>>) {
      ConfigParser<K> parser;
      it->second = parser.marshal(val);
    } else {
      std::string s(val);
      ConfigParser<K> parser;
      auto old = parser.unmarshal(std::get<S>(it->second));
      Result<T> v = parser.parse(old, s);
      if (!v) {
        return v.takeError();
      }
      // Recurse to the original type.
      return set<K>(std::move(*v));
    }
    return OK();
  }

private:
  using value_t = std::variant<uint64_t, std::string>;
  std::map<ConfigKey, value_t> config_map_;
};

} // namespace bpftrace
