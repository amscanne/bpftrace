#pragma once

#include <bpf/libbpf.h>
#include <cereal/access.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "ast/ast.h"
#include "bpffeature.h"
#include "bpfmap.h"
#include "bpfprogram.h"
#include "config.h"
#include "globalvars.h"
#include "required_resources.h"
#include "util/result.h"

namespace bpftrace {

// Representation of the entire BPF bytecode, with multiple functions.
//
// Encapsulates libbpf's 'struct bpf_object' as well as maps and programs.
//
// This is directly serializable via cereal.
class BpfBytecode : public ast::State<"bytecode"> {
public:
  BpfBytecode() = default;
  BpfBytecode(std::span<const std::byte> elf);
  BpfBytecode(std::span<uint8_t> elf);
  BpfBytecode(std::span<char> elf);

  void update_global_vars(BPFtrace &bpftrace,
                          globalvars::GlobalVarMap &&global_var_vals);
  uint64_t get_event_loss_counter(BPFtrace &bpftrace, int max_cpu_id);
  void load_progs(const RequiredResources &resources,
                  const BTF &btf,
                  BPFfeature &feature,
                  const Config &config);
  void attach_external();

  bool hasMap(MapType internal_type) const;
  bool hasMap(const StackType &stack_type) const;
  const BpfMap &getMap(const std::string &name) const;
  const BpfMap &getMap(MapType internal_type) const;
  const BpfMap &getMap(int map_id) const;
  void set_map_ids(RequiredResources &resources);

  const std::map<std::string, BpfMap> &maps() const;
  int countStackMaps() const;

private:
  void prepare_progs(const std::vector<ast::Probe> &probes,
                     const BTF &btf,
                     BPFfeature &feature,
                     const Config &config);

  bool all_progs_loaded();

  // Initialize from `elf_data_`, resets all maps, etc.
  void init();

  // We need a custom deleter for bpf_object which will call bpf_object__close.
  // Note that it is not possible to run bpf_object__close in ~BpfBytecode
  // as the desctuctor may be called upon move assignment.
  struct bpf_object_deleter {
    void operator()(struct bpf_object *object)
    {
      bpf_object__close(object);
    }
  };
  std::unique_ptr<struct bpf_object, bpf_object_deleter> bpf_object_;

  // Original ELF data for serialization.
  std::vector<std::byte> elf_data_;

  std::map<std::string, BpfMap> maps_;
  std::map<int, BpfMap *> maps_by_id_;
  std::map<std::string, BpfProgram> programs_;
  std::unordered_map<std::string, struct bpf_map *>
      section_names_to_global_vars_map_;

  friend class cereal::access;
  template <typename Archive>
  void save(Archive &archive) const
  {
    archive(elf_data_);
  }

  template <typename Archive>
  void load(Archive &archive)
  {
    archive(elf_data_);
    init();
  }
};

class HelperVerifierError : public std::runtime_error {
public:
  HelperVerifierError(const std::string &msg, bpf_func_id func_id_)
      : std::runtime_error(msg), func_id(func_id_) {};

  const bpf_func_id func_id;
};

} // namespace bpftrace
