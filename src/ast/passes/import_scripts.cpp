#include <algorithm>

#include "ast/ast.h"
#include "ast/passes/import_scripts.h"
#include "ast/passes/resolve_imports.h"

namespace bpftrace::ast {

static void import_ast(ASTContext &ast,
                       Node &node,
                       const ASTContext &other,
                       bool clone_macros)
{
  // The ordering of all probes is reversed before and after appending,
  // in order to provide a partial ordering over imports. Consider the
  // left node import -- this will wind up being the first thing initialized.
  std::ranges::reverse(ast.root->probes);

  // Clone all map declarations, subfunctions, etc. into the primary AST.
  // Note that we may choose not to inline all definitions in the future, and
  // define that namespace-based resolution is used for e.g. macro expansion,
  // function matching, etc. But for now, we just support a trivial
  // expansion.
  ast.diagnostics().add(std::move(other.diagnostics()));
  if (other.root) {
    for (const auto &stmt : other.root->c_statements) {
      ast.root->c_statements.push_back(clone(ast, node.loc, stmt));
    }
    for (const auto &decl : other.root->map_decls) {
      ast.root->map_decls.push_back(clone(ast, node.loc, decl));
    }
    for (const auto &fn : other.root->functions) {
      ast.root->functions.push_back(clone(ast, node.loc, fn));
    }
    for (const auto &probe : other.root->probes) {
      ast.root->probes.push_back(clone(ast, node.loc, probe));
    }
    // Macros are different, they can either be retained in the original
    // AST, or they can be loaded directly. This is controlled by the flag,
    // and is essentially used to control which deprecated features we find.
    if (clone_macros) {
      for (const auto &macro : other.root->macros) {
        ast.root->macros.push_back(clone(ast, node.loc, macro));
      }
    }
  }

  // See above. We re-reverse the set of probes available to provide the
  // intended partial ordering.
  std::ranges::reverse(ast.root->probes);
}

Pass CreateImportExternalScriptsPass()
{
  return Pass::create("ImportExternalScripts",
                      [](ASTContext &ast, Imports &imports) {
                        for (const auto &[name, obj] : imports.scripts) {
                          if (!obj.internal) {
                            import_ast(ast, obj.node, obj.ast, true);
                          }
                        }
                      });
}

Pass CreateImportInternalScriptsPass()
{
  return Pass::create("ImportInternalScripts",
                      [](ASTContext &ast, Imports &imports) {
                        // Macros are resolved as they are imported, we don't
                        // copy them into the main AST at this time. This means
                        // at they are exempt from the standard unstable feature
                        // checks, etc.
                        MacroRegistry registry;
                        for (const auto &[name, obj] : imports.scripts) {
                          if (obj.internal) {
                            import_ast(ast, obj.node, obj.ast, false);
                            registry.add(obj.ast);
                          }
                        }
                        registry.expand(ast);
                      });
}

} // namespace bpftrace::ast
