#include "ast/passes/pid_filter_pass.h"
<<<<<<< HEAD
#include "ast/passes/ap_probe_expansion.h"
=======
<<<<<<< HEAD
>>>>>>> 72046fd7 (inprog)
#include "ast/passes/attachpoint_passes.h"
    == == ==
    =
>>>>>>> 0c4403e6 (inprog)
#include "ast/passes/field_analyser.h"
#include "ast_matchers.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

<<<<<<< HEAD
namespace bpftrace::test::pid_filter_pass {

using bpftrace::test::ExprStatement;
using bpftrace::test::If;
using bpftrace::test::Integer;
using bpftrace::test::ProbeMatcher;
using bpftrace::test::Program;

using ::testing::_;
using ::testing::HasSubstr;

void test(const std::string& attach_points,
          bool has_pid,
          const std::vector<bool>& has_filters)
=======
        namespace bpftrace::test::pid_filter_pass
>>>>>>> 72046fd7 (inprog)
{
  using ::testing::_;
  using ::testing::HasSubstr;

<<<<<<< HEAD
  // Note that this constructs a program from the list of attachpoints,
  // and the body { 1 }, which we test for explicitly below.
  std::string input = attach_points + " { 1 }";
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  // N.B. No macro or tracepoint expansion.
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateProbeAndApExpansionPass())
                .add(ast::CreateFieldAnalyserPass())
                .add(ast::CreatePidFilterPass())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());

  std::vector<::testing::Matcher<const bpftrace::ast::Probe&>> matchers;
  for (const auto& has_filter : has_filters) {
    if (has_filter) {
      // The filter transforms the probe to a new block that has the if as the
      // final expression in the top.
      matchers.emplace_back(ProbeMatcher().WithBody(Block(
          {}, If(Binop(Operator::NE, Builtin("pid"), Integer(1)), _, _))));
    } else {
      matchers.emplace_back(ProbeMatcher().WithStatements({
          ExprStatement(Integer(1)),
      }));
    }
  }
  EXPECT_THAT(ast, Program().WithProbes(matchers));
}
=======
  void test(const std::string& input, bool has_pid, bool has_filter)
  {
    auto mock_bpftrace = get_mock_bpftrace();
    BPFtrace& bpftrace = *mock_bpftrace;
    if (has_pid) {
      bpftrace.procmon_ = std::make_unique<MockProcMon>(1);
    }

    ast::ASTContext ast("stdin", input);
    std::stringstream msg;
    msg << "\nInput:\n" << input << "\n\nOutput:\n";

    // N.B. No macro or tracepoint expansion.
    auto ok = ast::PassManager()
                  .put(ast)
                  .put(bpftrace)
                  .add(CreateParsePass())
                  .add(ast::CreateProbeExpansionPass())
                  .add(ast::CreateFieldAnalyserPass())
                  .add(ast::CreatePidFilterPass())
                  .run();
    ASSERT_TRUE(ok && ast.diagnostics().ok());

    std::string_view expected_ast = R"(
  if
   !=
    builtin: pid
    int: 1 :: [int64]
   then
   else
)";

    std::ostringstream out;
    ast::Printer printer(out);
    printer.visit(ast.root);

    if (has_filter) {
      EXPECT_THAT(out.str(), HasSubstr(expected_ast));
    } else {
      EXPECT_THAT(out.str(), Not(HasSubstr(expected_ast)));
    }
  }
>>>>>>> 72046fd7 (inprog)

  TEST(pid_filter_pass, add_filter)
  {
    std::vector<std::string> filter_probes = {
      "kprobe:f",
      "kretprobe:f",
      "fentry:f",
      "fexit:f",
      "tracepoint:category:event",
      "rawtracepoint:module:event",
    };

<<<<<<< HEAD
  for (auto& probe : filter_probes) {
    test(probe, true, { true });
=======
    for (auto& probe : filter_probes) {
      test(probe + " { 1 }", true, true);
    }
>>>>>>> 72046fd7 (inprog)
  }

<<<<<<< HEAD
TEST(pid_filter_pass, no_add_filter)
{
  // Sanity check: no pid, no filter
  test("kprobe:f", false, { false });
  test("profile:hz:99", false, { false });
=======
  TEST(pid_filter_pass, no_add_filter)
  {
    // Sanity check: no pid, no filter
    test("kprobe:f { 1 }", false, false);
    test("profile:hz:99 { 1 }", false, false);
>>>>>>> 72046fd7 (inprog)

    std::vector<std::string> no_filter_probes = {
      "begin",
      "end",
      "uprobe:/bin/sh:f",
      "uretprobe:/bin/sh:f",
      "usdt:sh:probe",
      "watchpoint:0x0:8:rw",
      "asyncwatchpoint:func1+arg2:8:rw",
      "profile:ms:1",
      "interval:s:1",
      "software:faults:1000",
      "hardware:cache-references:1000000",
    };

<<<<<<< HEAD
  for (auto& probe : no_filter_probes) {
    test(probe, true, { false });
=======
    for (auto& probe : no_filter_probes) {
      test(probe + " { 1 }", true, false);
    }
>>>>>>> 72046fd7 (inprog)
  }

<<<<<<< HEAD
=======
  TEST(pid_filter_pass, mixed_probes)
  {
    test("kprobe:f, uprobe:/bin/sh:f { 1 }", true, true);
    test("usdt:sh:probe, uprobe:/bin/sh:f, profile:ms:1 { 1 }", true, false);
  }

>>>>>>> 72046fd7 (inprog)
} // namespace bpftrace::test::pid_filter_pass
