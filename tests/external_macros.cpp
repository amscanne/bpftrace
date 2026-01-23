#include <llvm/Config/llvm-config.h>

#include "ast/passes/ap_probe_expansion.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/external_macros.h"
#include "driver.h"
#include "gtest/gtest.h"

namespace bpftrace::test::clang_parser {

static ast::ExternalMacros parse(
    const std::string &input,
    BPFtrace &bpftrace,
    bool result = true,
    const std::string &probe = "kprobe:sys_read { 1 }")
{
  auto extended_input = input + probe;
  ast::ASTContext ast("stdin", extended_input);

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateProbeAndApExpansionPass())
                .add(ast::CreateDefineExternalMacrosPass())
                .run();
  EXPECT_EQ(ok && ast.diagnostics().ok(), result);
  if (ok) {
    return std::move(ok->get<ast::ExternalMacros>());
  }
  return {};
}

TEST(external_macros, basic)
{
  BPFtrace bpftrace;

  auto macros = parse("#define FOO size_t\n k:f { 0 }", bpftrace);
  ASSERT_EQ(macros.macros.count("FOO"), 1U);
  EXPECT_EQ(macros.macros["FOO"], "size_t");

  macros = parse("#define _UNDERSCORE 314\n k:f { 0 }", bpftrace);
  ASSERT_EQ(macros.macros.count("_UNDERSCORE"), 1U);
  EXPECT_EQ(macros.macros["_UNDERSCORE"], "314");
}

} // namespace bpftrace::test::clang_parser
