#include <sstream>

#include <clang/Basic/Diagnostic.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Lex/PPCallbacks.h>
#include <clang/Lex/Preprocessor.h>
#include <clang/Tooling/Tooling.h>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/external_macros.h"
#include "ast/visitor.h"
#include "driver.h"

namespace bpftrace::ast {

char MacroError::ID;

void MacroError::log(llvm::raw_ostream &OS) const
{
  OS << message_;
}

namespace {

// Custom DiagnosticConsumer that captures error messages.
class ErrorCapturingConsumer : public clang::DiagnosticConsumer {
public:
  explicit ErrorCapturingConsumer(std::string &errors) : errors_(errors) {};

  void HandleDiagnostic(clang::DiagnosticsEngine::Level level,
                        const clang::Diagnostic &info) override
  {
    if (level >= clang::DiagnosticsEngine::Error) {
      llvm::SmallString<256> message;
      info.FormatDiagnostic(message);
      if (!errors_.empty()) {
        errors_ += "\n";
      }
      errors_ += message.str();
    }
  }

private:
  std::string &errors_;
};

class MacroCallback : public clang::PPCallbacks {
public:
  MacroCallback(clang::SourceManager &SM,
                std::map<std::string, std::string> &macros)
      : SM_(SM), macros_(macros) {};

  void MacroDefined(const clang::Token &MacroNameTok,
                    const clang::MacroDirective *MD) override
  {
    if (!MD || !MD->getMacroInfo())
      return;

    const clang::MacroInfo *MI = MD->getMacroInfo();

    // Skip function-like macros and builtins.
    if (MI->isFunctionLike() || MI->isBuiltinMacro())
      return;

    // Skip macros with no tokens (just #define FOO).
    if (MI->tokens_empty())
      return;

    std::string name = MacroNameTok.getIdentifierInfo()->getName().str();

    // Get the raw source text of the macro body.
    clang::SourceLocation Start = MI->tokens_begin()->getLocation();
    clang::SourceLocation End = MI->tokens_end()[-1].getEndLoc();
    clang::CharSourceRange Range = clang::CharSourceRange::getCharRange(Start,
                                                                        End);
    llvm::StringRef Text = clang::Lexer::getSourceText(Range,
                                                       SM_,
                                                       clang::LangOptions());
    if (!Text.empty()) {
      macros_[name] = Text.str();
    }
  }

private:
  clang::SourceManager &SM_;
  std::map<std::string, std::string> &macros_;
};

class MacroExtractorAction : public clang::PreprocessOnlyAction {
public:
  MacroExtractorAction(std::map<std::string, std::string> &macros,
                       std::string &errors)
      : macros_(macros), errors_(errors) {};

  bool BeginSourceFileAction(clang::CompilerInstance &CI) override
  {
    // Install our custom diagnostic consumer to capture error messages.
    CI.getDiagnostics().setClient(new ErrorCapturingConsumer(errors_), true);

    CI.getPreprocessor().addPPCallbacks(
        std::make_unique<MacroCallback>(CI.getSourceManager(), macros_));
    return true;
  }

private:
  std::map<std::string, std::string> &macros_;
  std::string &errors_;
};

class ExternalMacroExpander : public Visitor<ExternalMacroExpander> {
public:
  ExternalMacroExpander(ASTContext &ast, const ExternalMacros &macros)
      : ast_(ast), macros_(macros) {};

  using Visitor<ExternalMacroExpander>::visit;
  void visit(Expression &expr);

private:
  ASTContext &ast_;
  const ExternalMacros &macros_;
  std::vector<std::string> active_;
};

} // namespace

ast::Pass CreateDefineExternalMacrosPass(
    const std::vector<std::string> &extra_flags)
{
  return ast::Pass::create(
      "ExternalMacros",
      [extra_flags](ASTContext &ast) -> Result<ExternalMacros> {
        ExternalMacros result;

        // Serialize all C statements into a single source string.
        std::stringstream ss;
        for (const auto &stmt : ast.root->c_statements) {
          ss << stmt << "\n";
        }

        // Skip if there's nothing to process.
        auto input = ss.str();
        if (input.empty()) {
          return result;
        }

        // Build compiler arguments. We need -x c to tell clang this is C code,
        // and -E to run only the preprocessor.
        std::vector<std::string> args = { "-x", "c", "-E" };
        for (const auto &flag : extra_flags) {
          args.push_back(flag);
        }

        // Track any errors encountered during preprocessing.
        std::string errors;

        // Run clang to extract macros. The tooling API creates a virtual file
        // from the input string, so we just need a reasonable filename.
        bool success = clang::tooling::runToolOnCodeWithArgs(
            std::make_unique<MacroExtractorAction>(result.macros, errors),
            input,
            args,
            "input.c");

        if (!success) {
          if (errors.empty()) {
            return make_error<MacroError>("Clang preprocessing failed");
          }
          return make_error<MacroError>(std::move(errors));
        }

        return result;
      });
}

void ExternalMacroExpander::visit(Expression &expr)
{
  // N.B. We only support raw identifier macros. The way expansion works is
  // that we see if an expression is a bare identifier, then attempt expansion
  // recurisvely.
  if (auto *ident = expr.as<Identifier>()) {
    if (macros_.macros.contains(ident->ident)) {
      const auto it = macros_.macros.find(ident->ident);
      assert(it != macros_.macros.end());
      const auto &value = it->second;

      // Check for recursion.
      if (std::ranges::find(active_, ident->ident) != active_.end()) {
        ident->addError() << "Macro recursion: "
                          << util::str_join(active_, "->");
        return;
      }

      // Parse just the macro as an expression.
      ASTContext single_expr(ident->ident, value);
      Driver driver(single_expr);
      auto expanded = driver.parse_expr();
      if (!expanded) {
        ident->addError() << "unable to expand macro as an expression: "
                          << value;
        return;
      }

      // Expand the macro expression in place.
      expr.value = clone(ast_, ident->loc, expanded->value);

      // Recursively visit the potentially expanded expression, ensuring that
      // we can catch recursive expansion, per above.
      active_.emplace_back(ident->ident);
      Visitor<ExternalMacroExpander>::visit(expr);
      active_.pop_back();
      return;
    }
  }

  // Expand normally.
  Visitor<ExternalMacroExpander>::visit(expr);
}

Pass CreateExpandExternalMacrosPass()
{
  auto fn = [](ASTContext &ast, ExternalMacros &macros) {
    ExternalMacroExpander expander(ast, macros);
    expander.visit(ast.root);
  };

  return Pass::create("ExternalMacroExpansion", fn);
}

} // namespace bpftrace::ast
