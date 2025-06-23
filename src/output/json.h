#pragma once

#include <iostream>

#include "output/output.h"

namespace bpftrace::output {

class JsonOutput : public Output {
public:
  explicit JsonOutput(std::ostream &out = std::cout) : out_(out) {};

  void emit(const MapMessage &m) override;

private:
  std::ostream &out_;
};

} // namespace bpftrace::output
