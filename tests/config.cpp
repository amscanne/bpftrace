#include "config.h"
#include "gmock/gmock-matchers.h"
#include "gtest/gtest.h"

namespace bpftrace::test {

using ::testing::HasSubstr;

TEST(Config, get_and_set)
{
  auto config = Config();

  // check all the keys
  EXPECT_TRUE(bool(config.set<ConfigKey::cpp_demangle>(true)));
  EXPECT_EQ(config.must_get<ConfigKey::cpp_demangle>(), true);

  EXPECT_TRUE(bool(config.set<ConfigKey::lazy_symbolication>(true)));
  EXPECT_EQ(config.must_get<ConfigKey::lazy_symbolication>(), true);

  EXPECT_TRUE(bool(config.set<ConfigKey::log_size>(static_cast<uint64_t>(10))));
  EXPECT_EQ(config.must_get<ConfigKey::log_size>(), 10);

  EXPECT_TRUE(
      bool(config.set<ConfigKey::max_cat_bytes>(static_cast<uint64_t>(10))));
  EXPECT_EQ(config.must_get<ConfigKey::max_cat_bytes>(), 10);

  EXPECT_TRUE(
      bool(config.set<ConfigKey::max_map_keys>(static_cast<uint64_t>(10))));
  EXPECT_EQ(config.must_get<ConfigKey::max_map_keys>(), 10);

  EXPECT_TRUE(
      bool(config.set<ConfigKey::max_probes>(static_cast<uint64_t>(10))));
  EXPECT_EQ(config.must_get<ConfigKey::max_probes>(), 10);

  EXPECT_TRUE(
      bool(config.set<ConfigKey::max_bpf_progs>(static_cast<uint64_t>(10))));
  EXPECT_EQ(config.must_get<ConfigKey::max_bpf_progs>(), 10);

  EXPECT_TRUE(
      bool(config.set<ConfigKey::max_strlen>(static_cast<uint64_t>(10))));
  EXPECT_EQ(config.must_get<ConfigKey::max_strlen>(), 10);

  EXPECT_TRUE(bool(config.set<ConfigKey::max_type_res_iterations>(
      static_cast<uint64_t>(10))));
  EXPECT_EQ(config.must_get<ConfigKey::max_type_res_iterations>(), 10);

  EXPECT_TRUE(
      bool(config.set<ConfigKey::perf_rb_pages>(static_cast<uint64_t>(0))));
  EXPECT_EQ(config.must_get<ConfigKey::perf_rb_pages>(), 10);

  EXPECT_TRUE(bool(config.set<ConfigKey::str_trunc_trailer>("str")));
  EXPECT_EQ(config.must_get<ConfigKey::str_trunc_trailer>(), "str");

  EXPECT_TRUE(bool(config.set<ConfigKey::stack_mode>(StackMode::bpftrace)));
  EXPECT_EQ(config.must_get<ConfigKey::stack_mode>(), StackMode::bpftrace);

  // Test that this is also true by default, as a requirement.
  EXPECT_TRUE(config.must_get<ConfigKey::print_maps_on_exit>());
  EXPECT_TRUE(bool(config.set<ConfigKey::print_maps_on_exit>(false)));
  EXPECT_EQ(config.must_get<ConfigKey::print_maps_on_exit>(), false);

  EXPECT_TRUE(bool(config.set<ConfigKey::user_symbol_cache_type>(
      UserSymbolCacheType::per_program)));
  EXPECT_EQ(config.must_get<ConfigKey::user_symbol_cache_type>(),
            UserSymbolCacheType::per_program);

  EXPECT_TRUE(
      bool(config.set<ConfigKey::missing_probes>(ConfigMissingProbes::ignore)));
  EXPECT_EQ(config.must_get<ConfigKey::missing_probes>(),
            ConfigMissingProbes::ignore);

  EXPECT_FALSE(bool(config.set<ConfigKey::stack_mode>("invalid")));
  EXPECT_TRUE(bool(config.set<ConfigKey::stack_mode>("raw")));
  EXPECT_EQ(config.must_get<ConfigKey::stack_mode>(), StackMode::raw);
}

static void test_lookup_error(const std::string &key,
                              const std::string &err = "")
{
  auto ok = bpftrace::Config::lookup(key);
  if (err.empty()) {
    ASSERT_TRUE(bool(ok));
  } else {
    ASSERT_FALSE(bool(ok));
    std::stringstream ss;
    ss << ok.takeError();
    EXPECT_THAT(ss.str(), HasSubstr(err));
  }
}

TEST(Config, get_config_key)
{
  auto config = Config();
  std::string err_msg;
  test_lookup_error("log_size");
  test_lookup_error("Log_Size");
  test_lookup_error("bpftrace_log_sIze");
  test_lookup_error("BPFTRACE_LOG_SIZE");

  // check the error message
  test_lookup_error("logsize", "Unrecognized config variable: logsize");
  test_lookup_error("max_ast_nodes",
                    "max_ast_nodes can only be set as an environment variable");
}

TEST(ConfigSetter, set_user_symbol_cache_type)
{
  auto config = Config();

  EXPECT_FALSE(bool(config.set<ConfigKey::user_symbol_cache_type>("invalid")));
  EXPECT_TRUE(bool(config.set<ConfigKey::user_symbol_cache_type>("NONE")));
  EXPECT_EQ(config.must_get<ConfigKey::user_symbol_cache_type>(),
            UserSymbolCacheType::none);
}

TEST(ConfigSetter, set_missing_probes)
{
  auto config = Config();

  EXPECT_EQ(config.must_get<ConfigKey::missing_probes>(),
            ConfigMissingProbes::warn);
  EXPECT_FALSE(bool(config.set<ConfigKey::missing_probes>("invalid")));
  EXPECT_TRUE(bool(config.set<ConfigKey::missing_probes>("error")));
  EXPECT_EQ(config.must_get<ConfigKey::missing_probes>(),
            ConfigMissingProbes::error);
}

} // namespace bpftrace::test
