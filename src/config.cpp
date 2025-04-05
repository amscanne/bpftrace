#include <algorithm>
#include <cstring>
#include <fstream>
#include <set>

#include "config.h"
#include "log.h"
#include "types.h"

namespace bpftrace {

namespace {

struct DefaultSpec {
  ConfigKey key;
  std::variant<uint64_t, std::string> value;
};

} // namespace

char ConfigError::ID;
char RenameError::ID;

// /proc/sys/kernel/randomize_va_space >= 1
static bool is_aslr_enabled()
{
  std::string randomize_va_space_file = "/proc/sys/kernel/randomize_va_space";

  {
    std::ifstream file(randomize_va_space_file);
    if (file.fail()) {
      LOG(V1) << std::strerror(errno) << ": " << randomize_va_space_file;
      // conservatively return true
      return true;
    }

    std::string line;
    if (std::getline(file, line) && std::stoi(line) < 1)
      return false;
  }

  return true;
}

Config::Config(bool has_cmd)
{
  config_map_ = {
    { ConfigKey::cpp_demangle, static_cast<uint64_t>(1) },
    { ConfigKey::lazy_symbolication, static_cast<uint64_t>(1) },
    { ConfigKey::print_maps_on_exit, static_cast<uint64_t>(1) },
    { ConfigKey::unstable_import, static_cast<uint64_t>(0) },
    { ConfigKey::unstable_map_decl, static_cast<uint64_t>(0) },
#ifndef HAVE_BLAZESYM
    { ConfigKey::use_blazesym, static_cast<uint64_t>(0) },
#else
    { ConfigKey::use_blazesym, static_cast<uint64_t>(1) },
#endif
    { ConfigKey::log_size, static_cast<uint64_t>(1000000) },
    { ConfigKey::max_bpf_progs, static_cast<uint64_t>(1024) },
    { ConfigKey::max_cat_bytes, static_cast<uint64_t>(10240) },
    { ConfigKey::max_map_keys, static_cast<uint64_t>(4096) },
    { ConfigKey::max_probes, static_cast<uint64_t>(1024) },
    { ConfigKey::max_strlen, static_cast<uint64_t>(1024) },
    { ConfigKey::max_type_res_iterations, static_cast<uint64_t>(0) },
    { ConfigKey::on_stack_limit, static_cast<uint64_t>(32) },
    { ConfigKey::perf_rb_pages, static_cast<uint64_t>(64) },
    { ConfigKey::license, std::string("GPL") },
    { ConfigKey::str_trunc_trailer, std::string("..") },
    { ConfigKey::missing_probes,
      static_cast<uint64_t>(ConfigMissingProbes::warn) },
    { ConfigKey::stack_mode, static_cast<uint64_t>(StackMode::bpftrace) },
    // by default, cache user symbols per program if ASLR is disabled on system
    // or `-c` option is given
    {
        ConfigKey::user_symbol_cache_type,
        { static_cast<uint64_t>((has_cmd || !is_aslr_enabled())
                                    ? UserSymbolCacheType::per_program
                                    : UserSymbolCacheType::per_pid) },
    }
  };
};

// The strings in CONFIG_KEY_MAP AND ENV_ONLY match the env variables (minus the
// 'BPFTRACE_' prefix).
const std::map<std::string, ConfigKey> CONFIG_KEY_MAP = {
  { "cache_user_symbols", ConfigKey::user_symbol_cache_type },
  { "cpp_demangle", ConfigKey::cpp_demangle },
  { "lazy_symbolication", ConfigKey::lazy_symbolication },
  { "license", ConfigKey::license },
  { "log_size", ConfigKey::log_size },
  { "max_bpf_progs", ConfigKey::max_bpf_progs },
  { "max_cat_bytes", ConfigKey::max_cat_bytes },
  { "max_map_keys", ConfigKey::max_map_keys },
  { "max_probes", ConfigKey::max_probes },
  { "max_strlen", ConfigKey::max_strlen },
  { "max_type_res_iterations", ConfigKey::max_type_res_iterations },
  { "on_stack_limit", ConfigKey::on_stack_limit },
  { "perf_rb_pages", ConfigKey::perf_rb_pages },
  { "stack_mode", ConfigKey::stack_mode },
  { "str_trunc_trailer", ConfigKey::str_trunc_trailer },
  { "missing_probes", ConfigKey::missing_probes },
  { "print_maps_on_exit", ConfigKey::print_maps_on_exit },
#ifdef HAVE_BLAZESYM
  { "use_blazesym", ConfigKey::use_blazesym },
#else
  // This can never be matched as a key to be set.
  { " use_blazesym", ConfigKey::use_blazesym },
#endif
  { "unstable_import", ConfigKey::unstable_import },
  { "unstable_map_decl", ConfigKey::unstable_map_decl },
};

// These symbols are deprecated, and have been remapped elsewhere.
const std::map<std::string, std::string> DEPRECATED = {
  { "strlen", "max_strlen" },
  { "no_cpp_demangle", "cpp_demangle" },
  { "cat_bytes_max", "max_cat_bytes" },
  { "map_keys_max", "max_map_keys" },
};

// These are configuration names that are consumed elsewhere. We use this only
// to check if we should produce a more helpful error for the user.
const std::set<std::string> ENV_ONLY = {
  "btf",           "debug_output",   "kernel_build", "kernel_source",
  "max_ast_nodes", "verify_llvm_ir", "vmlinux",
};

// This is applied for all environment variables, and will also be accepted
// as part of the general configuration key (in lower case only).
constexpr std::string PREFIX = "BPFTRACE_";

Result<ConfigKey> Config::lookup(const std::string &original_key)
{
  std::string key;
  if (original_key.starts_with(PREFIX)) {
    key = original_key.substr(PREFIX.length());
  } else {
    key = original_key;
  }
  std::ranges::transform(key, key.begin(), [](unsigned char c) {
    return std::tolower(c);
  });
  auto dep = DEPRECATED.find(key);
  if (dep != DEPRECATED.end()) {
    return make_error<RenameError>(dep->second);
  }
  auto env = ENV_ONLY.find(key);
  if (env != ENV_ONLY.end()) {
    return make_error<ConfigError>(
        key + " can only be set as an environment variable");
  }
  auto k = CONFIG_KEY_MAP.find(key);
  if (k == CONFIG_KEY_MAP.end()) {
    return make_error<ConfigError>(key +
                                   " is not a known configuration option");
  }
  return k->second;
}

constexpr std::string UNSTABLE_PREFIX = "unstable_";

bool Config::is_unstable(const std::string &orig_key)
{
  std::string key(orig_key);
  std::ranges::transform(key, key.begin(), [](unsigned char c) {
    return std::tolower(c);
  });
  return key.starts_with(UNSTABLE_PREFIX);
}

template <ConfigKey K>
constexpr auto make_key_parser()
{
  return [](Config *config, const std::string &s) { return config->set<K>(s); };
}

template <size_t... values>
auto make_key_parsers([[maybe_unused]] std::index_sequence<values...> indices)
{
  using Fn = std::function<Result<OK>(Config *, const std::string &s)>;
  std::map<ConfigKey, Fn> fns;
  (fns.insert({ static_cast<ConfigKey>(values),
                make_key_parser<static_cast<ConfigKey>(values)>() }),
   ...);
  return fns;
}

auto all_key_parsers()
{
  return make_key_parsers(
      std::make_index_sequence<static_cast<size_t>(ConfigKey::__sentinel__)>());
}

Result<OK> Config::set(const std::string &key, const std::string &val)
{
  static auto parsers = all_key_parsers();
  auto k = Config::lookup(key);
  if (!k) {
    return k.takeError();
  }
  auto it = parsers.find(*k);
  if (it == parsers.end()) {
    return make_error<ConfigError>("Unable to parse key: " + key);
  }
  return it->second(this, val);
}

Result<OK> Config::set(const std::string &key, uint64_t value)
{
  std::stringstream ss;
  ss << value;
  return set(key, ss.str());
}

Result<OK> Config::load_environment()
{
  // Scan all known keys by their environment variable name, and if it is
  // present then set from the environment value.
  for (const auto &[key, _] : CONFIG_KEY_MAP) {
    std::string env = PREFIX + key;
    std::ranges::transform(env, env.begin(), [](unsigned char c) {
      return std::toupper(c);
    });
    const auto *cenv = getenv(env.c_str());
    if (cenv) {
      std::string value(cenv);
      auto ok = set(key, std::string(cenv));
      if (!ok) {
        return ok.takeError();
      }
    }
  }
  return OK();
}

} // namespace bpftrace
