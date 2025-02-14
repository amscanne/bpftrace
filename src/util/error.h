#pragma once

#include "llvm/Support/ErrorOr.h"

namespace bpftrace {

// In LLVM, ErrorOr maps a std::error_code, and Expected maps a richer Error
// object. The latter is preferred for newer code, as it allows richer
// expression of errors to be propagated. We map our internal Error type to
// this, but use the `Expected` type. In the future, this could map to
// something like `std::expected<T, Error>`, and we could replace the LLVM
// `Error` with our own.
//
// Out of the box, the LLVM `Error` class provides mandatory checking (errors
// cannot be ignored, they must be explicitly forward or consumed).
using Error = llvm::Error;
using ErrorOr = llvm::Expected;
using Success = llvm::ErrorSuccess;

// For error types, one can define custom error type by inheriting from
// `ErrorInfo`. For example, suppose you have the following:
//
//    class BpfVerifierError : public ErrorInfo<BpfVerifierError> {};
//
using ErrorInfo = llvm::ErrorInfo;

// But, we also have a number of standard error classes.
using FileError = llvm::FileError;
using OverflowError = llvm::OverflowError;
using NotFoundError = llvm::NotFoundError;
using ParseError = llvm::ParseError;
using EndOfFileError = llvm::EndOfFileError;
using UndefVarError = llvm::UndefVarError;
using StringError = llvm::StringError;

// All errors are constructed using `make_error<...>` with the error class.
using make_error = llvm::make_error;

// For error handling there are several cases to consider:
//
// (1) If you want to propagate the error, you can return as expected:
//
//   auto err = doAThing();
//   if (err) {
//     return err;
//   }
//
// (2) If you need to handle some cases, you can use `handleErrors`. Note that
// you will still need to propagate unhandled cases via (1).
//
//   auto err = doAThing();
//   auto left = handleErrors(std::move(err),
//                            [](const BpfVerifierError&) { ... });
//   if (left) {
//     return left;
//  }
//
//  (3) You can consume all errors with `handleAllErrors`.
using handleErrors = llvm::handleErrors;
using handleAllErrors = llvm::handleAllErrors;

};  // namespace bpftrace
