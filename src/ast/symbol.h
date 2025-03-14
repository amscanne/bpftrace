#pragma once

#include <iostream>
#include <string>
#include <vector>

namespace bpftrace::ast {

class Namespace {
public:
  Namespace(std::vector<std::string> &&components) : components_(components) {};

  const std::vector<std::string> &components() const { return components_; }

private:
  // The namespace is stored as its set of constituent components.
  std::vector<std::string> components_;
};

std::ostream& operator<<(std::ostream&, const Namespace&);

class Symbol {
public:
  Symbol(std::string s);

  const Namespace& ns() const { return ns_; }
  const std::string& ident() const { return ident_; }

private:
  Namespace ns_;
  std::string ident_;
};

std::ostream& operator<<(std::ostream&, const Symbol&);

} // namespace bpftrace::ast

namespace std {
  template<>
  struct hash<bpftrace::ast::Namespace> {
    size_t operator()(const bpftrace::ast::Namespace& ns) const {
      size_t h;
      for (const auto& comp : ns.components()) {
        h ^= std::hash<std::string>{}(comp);
      }
      return h;
    }
  };
  template<>
  struct hash<bpftrace::ast::Symbol> {
    size_t operator()(const bpftrace::ast::Symbol& sym) const {
      return std::hash<bpftrace::ast::Namespace>{}(sym.ns()) ^ std::hash<std::string>{}(sym.ident());
    }
  };
} // namespace std
