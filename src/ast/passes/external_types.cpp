#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include <clang/Basic/Diagnostic.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Lex/PPCallbacks.h>
#include <clang/Lex/Preprocessor.h>
#include <clang/Tooling/Tooling.h>
#include <sstream>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/external_types.h"
#include "ast/visitor.h"
#include "driver.h"

namespace bpftrace::ast {

char TypesError::ID;

void TypesError::log(llvm::raw_ostream &OS) const
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

// 1. Define the Visitor
class StructVisitor : public clang::RecursiveASTVisitor<StructVisitor> {
public:
  bool VisitRecordDecl(clang::RecordDecl *D)
  {
    // Only process actual struct definitions (not forward declarations)
    if (D->isStruct() && D->isThisDeclarationADefinition()) {
      llvm::outs() << "Found Struct: " << D->getNameAsString() << "\n";

      // Iterate over fields (members) of the struct
      for (const clang::FieldDecl *Field : D->fields()) {
        llvm::outs() << "  Field: " << Field->getType().getAsString() << " "
                     << Field->getNameAsString() << "\n";
      }
    }
    return true; // Continue traversal
  }
};

class CastResolver : public Visitor<CastResolver, std::optional<SizedType>> {
public:
  CastResolver(ASTContext &ast) : ast_(ast)
  {
  }

  using Visitor<CastResolver, std::optional<SizedType>>::visit;

  std::optional<SizedType> visit(NamedType &named)
  {
    // This takes the previous type_spec logic from the parser
    // and evaluates it locally. In the future, this will actually
    // parse the type from BTF. But this is a temporary measure.
    if (named.name == "void") {
      return CreateVoid();
    } else if (named.name == "bool") {
      return CreateBool();
    } else if (named.name == "char") {
      return CreateInt8();
    } else if (named.name == "int8") {
      return CreateInt8();
    } else if (named.name == "int16") {
      return CreateInt16();
    } else if (named.name == "int32") {
      return CreateInt32();
    } else if (named.name == "int64") {
      return CreateInt64();
    } else if (named.name == "uint8") {
      return CreateUInt8();
    } else if (named.name == "uint16") {
      return CreateUInt16();
    } else if (named.name == "uint32") {
      return CreateUInt32();
    } else if (named.name == "uint64") {
      return CreateUInt64();
    } else if (named.name == "inet") {
      return CreateInet(0);
    } else if (named.name == "buffer") {
      return CreateBuffer(0);
    } else if (named.name == "string") {
      return CreateString(0);
    } else if (named.name == "min_t") {
      return CreateMin(true);
    } else if (named.name == "max_t") {
      return CreateMax(true);
    } else if (named.name == "count_t") {
      return CreateCount();
    } else if (named.name == "sum_t") {
      return CreateSum(true);
    } else if (named.name == "avg_t") {
      return CreateAvg(true);
    } else if (named.name == "stats_t") {
      return CreateStats(true);
    } else if (named.name == "umin_t") {
      return CreateMin(false);
    } else if (named.name == "umax_t") {
      return CreateMax(false);
    } else if (named.name == "usum_t") {
      return CreateSum(false);
    } else if (named.name == "uavg_t") {
      return CreateAvg(false);
    } else if (named.name == "ustats_t") {
      return CreateStats(false);
    } else if (named.name == "timestamp") {
      return CreateTimestamp();
    } else if (named.name == "macaddr_t") {
      return CreateMacAddress();
    } else if (named.name == "cgroup_path_t") {
      return CreateCgroupPath();
    } else {
      return ident_to_record(named.name, 0);
    }
  }
  std::optional<SizedType> visit(TypeSpec &spec)
  {
    return visit(spec.value);
  }
  std::optional<SizedType> visit(PointerType &ptr)
  {
    if (auto elem = visit(ptr.pointee)) {
      return CreatePointer(*elem);
    }
    return std::nullopt;
  }
  std::optional<SizedType> visit(ArrayType &arr)
  {
    if (auto *named = arr.element_type.as<NamedType>()) {
      if (named->name == "inet") {
        return CreateInet(arr.size);
      } else if (named->name == "buffer") {
        return CreateBuffer(arr.size);
      } else if (named->name == "string") {
        return CreateString(arr.size);
      }
    }
    if (auto elem = visit(arr.element_type)) {
      return CreateArray(arr.size, *elem);
    }
    return std::nullopt;
  }
  std::optional<SizedType> visit(StructType &struct_type)
  {
    if (std::holds_alternative<std::string>(struct_type.detail)) {
      return ident_to_sized_type("struct " +
                                 std::get<std::string>(struct_type.detail));
    }
    return std::nullopt;
  }
  std::optional<SizedType> visit(UnionType &union_type)
  {
    if (std::holds_alternative<std::string>(union_type.detail)) {
      return ident_to_sized_type("union " +
                                 std::get<std::string>(union_type.detail));
    }
    return std::nullopt;
  }
  std::optional<SizedType> visit(EnumType &enum_type)
  {
    return ident_to_sized_type(enum_type.name);
  }
  std::optional<SizedType> visit(Expression &expr)
  {
    if (auto *cast = expr.as<CastOrBinop>()) {
      // Use the legacy rules for the grammar to resolve the type.
    }
  }

private:
  ASTContext &ast_;
};

} // namespace

ast::Pass CreateDefineExternalTypesPass()
{
  return ast::Pass::create("ExternalTypes",
                           [](ASTContext &ast) -> Result<ExternalTypes> {
                             CastResolver().visit(ast.root);
                           });
}

} // namespace bpftrace::ast
