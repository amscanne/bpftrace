#include "driver.h"
#include "parser.tab.hh"

extern void set_source_string(const std::string *s);
extern int yylex_init(yyscan_t *scanner);
extern int yylex_destroy(yyscan_t yyscanner);

namespace bpftrace {

char NodesError::ID;
void NodesError::log(llvm::raw_ostream &OS) const
{
  OS << "node count (" << count_ << ") exceeds the limit (" << max_ << ")";
}

void Driver::parse()
{
  // Reset state on every pass.
  loc.initialize();
  struct_type.clear();
  buffer.clear();

  yyscan_t scanner;
  yylex_init(&scanner);
  Parser parser(*this, scanner);
  if (debug) {
    parser.set_debug_level(1);
  }
  set_source_string(&ctx.source_->contents);
  parser.parse();
  yylex_destroy(scanner);
}

void Driver::error(const location &l, const std::string &m)
{
  // This path is normally not allowed, however we don't yet have nodes
  // constructed. Therefore, we add diagnostics directly via the private field.
  ctx.diagnostics_->addError(ctx.wrap(l)) << m;
}

ast::Pass CreateParsePass(bool debug)
{
  return ast::Pass::create(
      "parse", [debug](ast::ASTContext &ast, BPFtrace &b) -> Result<OK> {
        Driver driver(ast, b, debug);
        driver.parse();

        // Before proceeding, ensure that the size of the AST isn't past
        // prescribed limits. This functionality goes back to 80642a994, where
        // it was added in order to prevent stack overflow during fuzzing. It
        // traveled through the passes and visitor pattern, and this is a final
        // return to the simplest possible form. It is not necessary to walk the
        // full AST in order to determine the number of nodes. This can be done
        // before any passes.
        if (ast.diagnostics().ok()) {
          auto node_count = ast.node_count();
          if (node_count > b.max_ast_nodes_) {
            return make_error<NodesError>(node_count, b.max_ast_nodes_);
          }
        }
        return OK();
      });
}

} // namespace bpftrace
