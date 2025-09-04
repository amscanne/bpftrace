#include <set>

#include "ast/ast.h"
#include "ast/passes/type_graph.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

class TypeGraphDatabase {
public:
  using resolver = std::function<void()>;

  void resolve(const Node &node, SizedType &&type)
  {
    // Save the type.
    types.emplace(&node, std::move(type));

    // Fire all associated resolvers.
    for (auto &fn : resolvers[&node]) {
      fn();
    }
  }

  void wait(std::initializer_list<const Node *> nodes, resolver fn)
  {
    if (nodes.size() == 0) {
      fn();
    } else if (nodes.size() == 1) {
      // This is the primary path, if the type is resolved already,
      // the function still gets emplaced but fired immediately.
      const auto *node = *nodes.begin();
      auto &newfn = resolvers[&node].emplace_back(fn);
      if (types.contains(node)) {
        newfn();
      }
    } else {
      // We construct a shared set, and chain a function to each
      // member that we are waiting for that checks against the set.
      size_t total = nodes.size();
      auto done = std::make_shared<std::set<const Node *>>();
      for (auto &node : nodes) {
        wait({ node }, [total, done, node, fn] {
          done->insert(node);
          if (done->size() == total) {
            fn();
          }
        });
      }
    }
  }

  const Variable *variable(const Variable *orig)
  {
    // This needs to look up the variable in the current scope,
    // and identify the original instance that will be used as
    // the canonical watchpoint for the types.
    return orig;
  }

  const Map *map(const Map *orig)
  {
    // Is there an existing one?
    if (canonical_maps.contains(orig->ident)) {
      return canonical_maps[orig->ident];
    }
    // We're not the canonical entry.
    canonical_maps[orig->ident] = orig;
    return orig;
  }

private:
  std::map<const Node *, std::vector<resolver>> resolvers;
  std::map<const Node *, SizedType> types;
  std::map<const Variable *, const Variable *> canonical_vars;
  std::map<const std::string, const Map *> canonical_maps;
};

namespace {

class TypeGraphBuilder : public Visitor<TypeGraphBuilder> {
public:
  TypeGraphBuilder(TypeGraphDatabase &db) : db_(db){};

  void visit(Integer &integer);
  void visit(NegativeInteger &integer);
  void visit(Boolean &boolean);
  void visit(String &string);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(Map &map);
  void visit(MapAddr &map_addr);
  void visit(Variable &var);
  void visit(VariableAddr &var_addr);
  void visit(Binop &binop);
  void visit(Unop &unop);
  void visit(IfExpr &if_expr);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
  void visit(TupleAccess &acc);
  void visit(MapAccess &acc);
  void visit(Cast &cast);
  void visit(Tuple &tuple);
  void visit(Expression &expr);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(BlockExpr &block);

private:
  TypeGraphDatabase &db_;
};

} // namespace

void TypeGraphBuilder::visit(Integer &integer)
{
  if (integer.force_unsigned ||
      integer.value > std::numeric_limits<int64_t>::max()) {
    db_.resolve(integer, CreateInteger(integer.bytes * 8, false));
  } else {
    db_.resolve(integer, CreateInteger(integer.bytes * 8, true));
  }
}

void TypeGraphBuilder::visit(NegativeInteger &integer)
{
  db_.resolve(integer, CreateInteger(integer.bytes * 8, true));
}

void TypeGraphBuilder::visit(Boolean &boolean)
{
  db_.resolve(boolean, CreateBool());
}

void TypeGraphBuilder::visit(String &string)
{
  db_.resolve(string, CreateString(string.value.size() + 1));
}

void TypeGraphBuilder::visit(Sizeof &szof)
{
  // These are always uint64_t for the purposes of type resolution, although
  // they will be folded later.
  db_.resolve(szof, CreateUInt64());
}

void TypeGraphBuilder::visit(Offsetof &offof)
{
  // See as `sizeof`.
  db_.resolve(offof, CreateUInt64());
}

void TypeGraphBuilder::visit(MapAddr &map_addr)
{
  db_.wait({ map_addr.map }, [&] {
    // Note that we don't have the ability to construct the proper map type
    // (the struct with four entries), so just indicate that it is a void*.
    db_.resolve(map_addr, CreatePointer(CreateVoid()));
  });
}

void TypeGraphBuilder::visit(Variable &var)
{
  auto *canonical_var = db_.variable(&var);
  db_.wait(
      { canonical_var },
      [&] { db_.resolve(var, db_.get_type(canonical_var)); },
      scoped_var);
}

void TypeGraphBuilder::visit(VariableAddr &var_addr)
{
  check_variable(*var_addr.var,
                 false /* Don't warn if variable hasn't been assigned yet */);
  if (auto *found = find_variable(var_addr.var->ident)) {
    if (!found->type.IsNoneTy()) {
      var_addr.var_addr_type = CreatePointer(found->type, found->type.GetAS());
    }
    // We can't know if the pointer to a scratch variable was passed
    // to an external function for assignment so just mark it as assigned.
    found->was_assigned = true;
  }
  if (is_final_pass() && var_addr.var_addr_type.IsNoneTy()) {
    var_addr.addError() << "No type available for variable "
                        << var_addr.var->ident;
  }
}

void TypeGraphBuilder::visit(ArrayAccess &arr)
{
  visit(arr.expr);
  visit(arr.indexpr);

  // Resolve the main expression.
  types_.wait(
      [&] {
        const auto &ty = types_.get(arr.expr);
        if (!ty.IsArrayTy() && !ty.IsPtrTy()) {
          arr.addError() << "The array index operator [] can only be "
                            "used on arrays and pointers, found "
                         << ty.GetTy() << ".";
          return;
        }
        if (ty.IsPtrTy() && ty.GetPointeeTy()->GetSize() == 0) {
          arr.addError() << "The array index operator [] cannot be used "
                            "on a pointer to an unsized type (void *).";
          return;
        }
        if (type.IsArrayTy()) {
          if (auto *integer = arr.indexpr.as<Integer>()) {
            size_t num = type.GetNumElements();
            if (num != 0 && static_cast<size_t>(integer->value) >= num) {
              arr.addError() << "the index " << integer->value
                             << " is out of bounds for array of size " << num;
            }
          }
        }
        if (type.IsArrayTy()) {
          types_.resolve(arr, ty.GetElementTy());
        } else if (type.IsPtrTy()) {
          types_.resolve(arr, ty.GetPointeeTy());
        }
      },
      arr.expr);

  // Check the index.
  types_.wait(
      [&] {
        const auto &ty = types_.get(arr.indexpr);
        if (!ty.IsIntTy() || ty.IsSigned()) {
          arr.addError() << "The array index operator [] only "
                            "accepts positive (unsigned) integer indices. Got: "
                         << ty.GetTy() << ".";
          return;
        }
      },
      arr.indexpr);

  arr.element_type.SetAS(type.GetAS());

  // BPF verifier cannot track BTF information for double pointers so we
  // cannot propagate is_internal for arrays of pointers and we need to reset
  // it on the array type as well. Indexing a pointer as an array also can't
  // be verified, so the same applies there.
  if (arr.element_type.IsPtrTy() || type.IsPtrTy()) {
    arr.element_type.is_internal = false;
  } else {
    arr.element_type.is_internal = type.is_internal;
  }
}

void TypeGraphBuilder::visit(TupleAccess &acc)
{
  visit(acc.expr);
  const SizedType &type = acc.expr.type();

  if (!type.IsTupleTy()) {
    if (is_final_pass()) {
      acc.addError() << "Can not access index '" << acc.index
                     << "' on expression of type '" << type << "'";
    }
    return;
  }

  bool valid_idx = acc.index < type.GetFields().size();

  // We may not have inferred the full type of the tuple yet in early passes
  // so wait until the final pass.
  if (!valid_idx && is_final_pass()) {
    acc.addError() << "Invalid tuple index: " << acc.index << ". Found "
                   << type.GetFields().size() << " elements in tuple.";
  }

  if (valid_idx) {
    acc.element_type = type.GetField(acc.index).type;
  }
}

void TypeGraphBuilder::binop_int(Binop &binop)
{
  bool lsign = binop.left.type().IsSigned();
  bool rsign = binop.right.type().IsSigned();

  auto &left = binop.left;
  auto &right = binop.right;
  std::optional<int64_t> left_literal;
  std::optional<int64_t> right_literal;
  if (auto *integer = left.as<Integer>())
    left_literal.emplace(static_cast<int64_t>(integer->value));
  if (auto *integer = left.as<NegativeInteger>())
    left_literal.emplace(integer->value);
  if (auto *integer = right.as<Integer>())
    right_literal.emplace(static_cast<int64_t>(integer->value));
  if (auto *integer = right.as<NegativeInteger>())
    right_literal.emplace(integer->value);

  // First check if operand signedness is the same
  if (lsign != rsign) {
    // Convert operands to unsigned if it helps make (lsign == rsign)
    //
    // For example:
    //
    // unsigned int a;
    // if (a > 10) ...;
    //
    // No warning should be emitted as we know that 10 can be
    // represented as unsigned int
    if (lsign && !rsign && left_literal && left_literal.value() >= 0) {
      lsign = false;
    }
    // The reverse (10 < a) should also hold
    else if (!lsign && rsign && right_literal && right_literal.value() >= 0) {
      rsign = false;
    } else {
      switch (binop.op) {
        case Operator::EQ:
        case Operator::NE:
        case Operator::LE:
        case Operator::GE:
        case Operator::LT:
        case Operator::GT:
          binop.addWarning() << "comparison of integers of different signs: '"
                             << left.type() << "' and '" << right.type() << "'"
                             << " can lead to undefined behavior";
          break;
        case Operator::PLUS:
        case Operator::MINUS:
        case Operator::MUL:
        case Operator::DIV:
        case Operator::MOD:
          binop.addWarning() << "arithmetic on integers of different signs: '"
                             << left.type() << "' and '" << right.type() << "'"
                             << " can lead to undefined behavior";
          break;
        default:
          break;
      }
    }
  }

  // Next, warn on any operations that require signed division.
  //
  // SDIV is not implemented for bpf. See Documentation/bpf/bpf_design_QA
  // in kernel sources
  if (binop.op == Operator::DIV || binop.op == Operator::MOD) {
    // Convert operands to unsigned if possible
    if (lsign && left_literal && left_literal.value() >= 0)
      lsign = false;
    if (rsign && right_literal && right_literal.value() >= 0)
      rsign = false;

    // If they're still signed, we have to warn
    if (lsign || rsign) {
      binop.addWarning() << "signed operands for '" << opstr(binop)
                         << "' can lead to undefined behavior "
                         << "(cast to unsigned to silence warning)";
    }
  }
}

void TypeGraphBuilder::binop_array(Binop &binop)
{
  const auto &lht = binop.left.type();
  const auto &rht = binop.right.type();
  if (binop.op != Operator::EQ && binop.op != Operator::NE) {
    binop.addError() << "The " << opstr(binop)
                     << " operator cannot be used on arrays.";
  }

  if (lht.GetNumElements() != rht.GetNumElements()) {
    binop.addError()
        << "Only arrays of same size support comparison operators.";
  }

  if (!lht.GetElementTy()->IsIntegerTy() || lht != rht) {
    binop.addError()
        << "Only arrays of same sized integer support comparison operators.";
  }
}

void TypeGraphBuilder::binop_ptr(Binop &binop)
{
  const auto &lht = binop.left.type();
  const auto &rht = binop.right.type();

  bool left_is_ptr = lht.IsPtrTy();
  const auto &ptr = left_is_ptr ? lht : rht;
  const auto &other = left_is_ptr ? rht : lht;

  bool compare = false;
  bool logical = false;

  // Do what C does
  switch (binop.op) {
    case Operator::EQ:
    case Operator::NE:
    case Operator::LE:
    case Operator::GE:
    case Operator::LT:
    case Operator::GT:
      compare = true;
      break;
    case Operator::LAND:
    case Operator::LOR:
      logical = true;
      break;
    default:;
  }

  auto invalid_op = [&binop, &lht, &rht]() {
    binop.addError() << "The " << opstr(binop)
                     << " operator can not be used on expressions of types "
                     << lht << ", " << rht;
  };

  // Binop on two pointers
  if (other.IsPtrTy()) {
    if (compare) {
      if (is_final_pass()) {
        const auto *le = lht.GetPointeeTy();
        const auto *re = rht.GetPointeeTy();
        if (*le != *re) {
          auto &warn = binop.addWarning();
          warn << "comparison of distinct pointer types: " << *le << ", "
               << *re;
          warn.addContext(binop.left.loc()) << "left (" << *le << ")";
          warn.addContext(binop.right.loc()) << "right (" << *re << ")";
        }
      }
    } else if (!logical) {
      invalid_op();
    }
  }
  // Binop on a pointer and (int or bool)
  else if (other.IsIntTy() || other.IsBoolTy()) {
    // sum is associative but minus only works with pointer on the left hand
    // side
    if (binop.op == Operator::MINUS && !left_is_ptr)
      invalid_op();
    else if (binop.op == Operator::PLUS || binop.op == Operator::MINUS)
      binop.result_type = CreatePointer(*ptr.GetPointeeTy(), ptr.GetAS());
    else if (!compare && !logical)
      invalid_op();
  }
  // Might need an additional pass to resolve the type
  else if (other.IsNoneTy()) {
    if (is_final_pass()) {
      invalid_op();
    }
  }
  // Binop on a pointer and something else
  else {
    invalid_op();
  }
}

void TypeGraphBuilder::visit(Binop &binop)
{
  visit(binop.left);
  visit(binop.right);

  const auto &lht = binop.left.type();
  const auto &rht = binop.right.type();
  bool lsign = binop.left.type().IsSigned();
  bool rsign = binop.right.type().IsSigned();
  bool is_int_binop = (lht.IsCastableMapTy() || lht.IsIntTy() ||
                       lht.IsBoolTy()) &&
                      (rht.IsCastableMapTy() || rht.IsIntTy() ||
                       rht.IsBoolTy());

  bool is_signed = lsign && rsign;
  bool is_comparison = is_comparison_op(binop.op);
  switch (binop.op) {
    case Operator::LEFT:
    case Operator::RIGHT:
      is_signed = lsign;
      break;
    default:
      break;
  }

  if (is_comparison) {
    binop.result_type = CreateBool();
  }

  if (lht.IsBoolTy() && rht.IsBoolTy()) {
    binop.result_type = CreateBool();
    return;
  }

  if (lht.IsPtrTy() || rht.IsPtrTy()) {
    binop_ptr(binop);
    return;
  }

  if (!is_comparison) {
    if (is_int_binop) {
      // Implicit size promotion to larger of the two
      auto size = std::max(lht.GetSize(), rht.GetSize());
      binop.result_type = CreateInteger(size * 8, is_signed);
    } else {
      // Default type - will be overriden below as necessary
      binop.result_type = CreateInteger(64, is_signed);
    }
  }

  auto addr_lhs = binop.left.type().GetAS();
  auto addr_rhs = binop.right.type().GetAS();

  // if lhs or rhs has different addrspace (not none), then set the
  // addrspace to none. This preserves the behaviour for x86.
  if (addr_lhs != addr_rhs && addr_lhs != AddrSpace::none &&
      addr_rhs != AddrSpace::none) {
    if (is_final_pass())
      binop.addWarning() << "Addrspace mismatch";
    binop.result_type.SetAS(AddrSpace::none);
  }
  // Associativity from left to right for binary operator
  else if (addr_lhs != AddrSpace::none) {
    binop.result_type.SetAS(addr_lhs);
  } else {
    // In case rhs is none, then this triggers warning in
    // selectProbeReadHelper.
    binop.result_type.SetAS(addr_rhs);
  }

  if (!is_final_pass()) {
    return;
  }

  if (is_int_binop) {
    binop_int(binop);
  } else if (lht.IsArrayTy() && rht.IsArrayTy()) {
    binop_array(binop);
  } else if (lht.IsPtrTy() || rht.IsPtrTy()) {
    // This case is caught earlier, just here for readability of the if/else
    // flow
  }
  // Compare type here, not the sized type as we it needs to work on strings
  // of different lengths
  else if (lht.GetTy() != rht.GetTy()) {
    auto &err = binop.addError();
    err << "Type mismatch for '" << opstr(binop) << "': comparing " << lht
        << " with " << rht;
    err.addContext(binop.left.loc()) << "left (" << lht << ")";
    err.addContext(binop.right.loc()) << "right (" << rht << ")";
  }
  // Also allow combination like reg("sp") + 8
  else if (binop.op != Operator::EQ && binop.op != Operator::NE) {
    binop.addError() << "The " << opstr(binop)
                     << " operator can not be used on expressions of types "
                     << lht << ", " << rht;
  }
}

void TypeGraphBuilder::visit(Unop &unop)
{
  if (unop.op == Operator::INCREMENT || unop.op == Operator::DECREMENT) {
    // Handle ++ and -- before visiting unop.expr, because these
    // operators should be able to work with undefined maps.
    if (auto *acc = unop.expr.as<MapAccess>()) {
      auto *maptype = get_map_type(*acc->map);
      if (!maptype) {
        // Doing increments or decrements on the map type implements that
        // it is done on an integer. Maps are always coerced into larger
        // integers, so this should not conflict with different assignments.
        assign_map_type(*acc->map, CreateInt64(), acc->map);
      }
    } else if (!unop.expr.is<Variable>()) {
      unop.addError() << "The " << opstr(unop)
                      << " operator must be applied to a map or variable";
    }
  }

  visit(unop.expr);

  auto valid_ptr_op = false;
  switch (unop.op) {
    case Operator::INCREMENT:
    case Operator::DECREMENT:
    case Operator::MUL:
      valid_ptr_op = true;
      break;
    default:;
  }

  const SizedType &type = unop.expr.type();
  if (is_final_pass()) {
    bool invalid = false;
    // Unops are only allowed on ints (e.g. ~$x), dereference only on pointers
    // and context (we allow args->field for backwards compatibility)
    if (type.IsBoolTy()) {
      invalid = unop.op != Operator::LNOT;
    } else if (!type.IsIntegerTy() &&
               !((type.IsPtrTy() || type.IsCtxAccess()) && valid_ptr_op)) {
      invalid = true;
    }
    if (invalid) {
      unop.addError() << "The " << opstr(unop)
                      << " operator can not be used on expressions of type '"
                      << type << "'";
    }
  }

  if (unop.op == Operator::MUL) {
    if (type.IsPtrTy()) {
      unop.result_type = SizedType(*type.GetPointeeTy());
      if (type.IsCtxAccess())
        unop.result_type.MarkCtxAccess();
      unop.result_type.is_internal = type.is_internal;
      unop.result_type.SetAS(type.GetAS());
    } else if (type.IsRecordTy()) {
      // We allow dereferencing "args" with no effect (for backwards compat)
      if (type.IsCtxAccess())
        unop.result_type = type;
      else {
        unop.addError() << "Can not dereference struct/union of type '"
                        << type.GetName() << "'. It is not a pointer.";
      }
    } else if (type.IsIntTy()) {
      unop.result_type = CreateUInt64();
    }
  } else if (unop.op == Operator::LNOT) {
    unop.result_type = CreateBool();
  } else if (type.IsPtrTy() && valid_ptr_op) {
    unop.result_type = unop.expr.type();
  } else {
    unop.result_type = CreateInteger(64, type.IsSigned());
  }
}

void TypeGraphBuilder::visit(IfExpr &if_expr)
{
  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);

  const Type &cond = if_expr.cond.type().GetTy();
  const auto &lhs = if_expr.left.type();
  const auto &rhs = if_expr.right.type();

  if (!lhs.IsSameType(rhs)) {
    if (is_final_pass()) {
      if_expr.addError() << "Branches must return the same type: " << "have '"
                         << lhs << "' and '" << rhs << "'";
    }
    // This assignment is just temporary to prevent errors
    // before the final pass
    if_expr.result_type = lhs;
    return;
  }

  if (lhs.IsStack() && lhs.stack_type != rhs.stack_type) {
    // TODO: fix this for different stack types
    if_expr.addError() << "Branches must have the same stack type on the right "
                          "and left sides.";
    return;
  }

  if (is_final_pass() && cond != Type::integer && cond != Type::pointer &&
      cond != Type::boolean) {
    if_expr.addError() << "Invalid condition: " << cond;
    return;
  }

  if (lhs.IsIntegerTy()) {
    if_expr.result_type = CreateInteger(64, lhs.IsSigned());
  } else {
    auto lsize = lhs.GetSize();
    auto rsize = rhs.GetSize();
    if (lhs.IsTupleTy()) {
      if_expr.result_type = create_merged_tuple(rhs, lhs);
    } else {
      if_expr.result_type = lsize > rsize ? lhs : rhs;
    }
  }
}

void TypeGraphBuilder::visit(Unroll &unroll)
{
  visit(unroll.expr);

  auto *integer = unroll.expr.as<Integer>();
  if (!integer) {
    unroll.addError() << "invalid unroll value";
    return;
  }

  if (integer->value > static_cast<uint64_t>(100)) {
    unroll.addError() << "unroll maximum value is 100";
  } else if (integer->value < static_cast<uint64_t>(1)) {
    unroll.addError() << "unroll minimum value is 1";
  }

  visit(unroll.block);
}

void TypeGraphBuilder::visit(Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      if (jump.return_value) {
        visit(jump.return_value);
      }
      if (auto *subprog = dynamic_cast<Subprog *>(top_level_node_)) {
        const auto &ty = subprog->return_type->type();
        if (is_final_pass() && !ty.IsNoneTy() &&
            (ty.IsVoidTy() != !jump.return_value.has_value() ||
             (jump.return_value.has_value() &&
              jump.return_value->type() != ty))) {
          jump.addError() << "Function " << subprog->name << " is of type "
                          << ty << ", cannot return "
                          << (jump.return_value.has_value()
                                  ? jump.return_value->type()
                                  : CreateVoid());
        }
      }
      break;
    case JumpType::BREAK:
    case JumpType::CONTINUE:
      if (!in_loop())
        jump.addError() << opstr(jump) << " used outside of a loop";
      break;
    default:
      jump.addError() << "Unknown jump: '" << opstr(jump) << "'";
  }
}

void TypeGraphBuilder::visit(While &while_block)
{
  visit(while_block.cond);

  loop_depth_++;
  visit(while_block.block);
  loop_depth_--;
}

void TypeGraphBuilder::visit(For &f)
{
  if (f.iterable.is<Range>() && !bpftrace_.feature_->has_helper_loop()) {
    f.addError() << "Missing required kernel feature: loop";
  }
  if (f.iterable.is<Map>() &&
      !bpftrace_.feature_->has_helper_for_each_map_elem()) {
    f.addError() << "Missing required kernel feature: for_each_map_elem";
  }
  if (auto *map = f.iterable.as<Map>()) {
    if (!is_first_pass() && !map_val_.contains(map->ident)) {
      map->addError() << "Undefined map: " << map->ident;
    }
  }

  // For-loops are implemented using the bpf_for_each_map_elem or bpf_loop
  // helper functions, which requires them to be rewritten into a callback
  // style.
  //
  // Pseudo code for the transformation we apply:
  //
  // Before:
  //     PROBE {
  //       @map[0] = 1;
  //       for ($kv : @map) {
  //         [LOOP BODY]
  //       }
  //     }
  //
  // After:
  //     PROBE {
  //       @map[0] = 1;
  //       bpf_for_each_map_elem(@map, &map_for_each_cb, 0, 0);
  //     }
  //     long map_for_each_cb(bpf_map *map,
  //                          const void *key,
  //                          void *value,
  //                          void *ctx) {
  //       $kv = ((uint64)key, (uint64)value);
  //       [LOOP BODY]
  //     }
  //
  //
  // To allow variables to be shared between the loop callback and the main
  // program, some extra steps are taken:
  //
  // 1. Determine which variables need to be shared with the loop callback
  // 2. Pack pointers to them into a context struct
  // 3. Pass pointer to the context struct to the callback function
  // 4. In the callback, override the shared variables so that they read and
  //    write through the context pointers instead of directly from their
  //    original addresses
  //
  // Example transformation with context:
  //
  // Before:
  //     PROBE {
  //       $str = "hello";
  //       $not_shared = 2;
  //       $len = 0;
  //       @map[11, 12] = "c";
  //       for ($kv : @map) {
  //         print($str);
  //         $len++;
  //       }
  //       print($len);
  //       print($not_shared);
  //     }
  //
  // After:
  //     struct ctx_t {
  //       string *str;
  //       uint64 *len;
  //     };
  //     PROBE {
  //       $str = "hello";
  //       $not_shared = 2;
  //       $len = 0;
  //       @map[11, 12] = "c";
  //
  //       ctx_t ctx { .str = &$str, .len = &$len };
  //       bpf_for_each_map_elem(@map, &map_for_each_cb, &ctx, 0);
  //
  //       print($len);
  //       print($not_shared);
  //     }
  //     long map_for_each_cb(bpf_map *map,
  //                          const void *key,
  //                          void *value,
  //                          void *ctx) {
  //       $kv = (((uint64, uint64))key, (string)value);
  //       $str = ((ctx_t*)ctx)->str;
  //       $len = ((ctx_t*)ctx)->len;
  //
  //       print($str);
  //       $len++;
  //     }

  // Validate decl.
  const auto &decl_name = f.decl->ident;
  if (find_variable(decl_name)) {
    f.decl->addError() << "Loop declaration shadows existing variable: " +
                              decl_name;
  }

  visit(f.iterable);

  // Validate the iterable.
  if (auto *map = f.iterable.as<Map>()) {
    if (!map->type().IsMapIterableTy()) {
      map->addError() << "Loop expression does not support type: "
                      << map->type();
      return;
    }
  } else if (auto *range = f.iterable.as<Range>()) {
    if (is_final_pass()) {
      if (!range->start.type().IsIntTy()) {
        range->addError()
            << "Loop range requires an integer for the start value";
      }
      if (!range->end.type().IsIntTy()) {
        range->addError() << "Loop range requires an integer for the end value";
      }
    }
  }

  // Validate body. We may relax this in the future.
  CollectNodes<Jump> jumps;
  jumps.visit(f.block);
  for (const Jump &n : jumps.nodes()) {
    if (n.ident == JumpType::RETURN) {
      n.addError() << "'" << opstr(n)
                   << "' statement is not allowed in a for-loop";
    }
  }

  if (!ctx_.diagnostics().ok())
    return;

  // Collect a list of unique variables which are referenced in the loop's
  // body and declared before the loop. These will be passed into the loop
  // callback function as the context parameter.
  std::unordered_set<std::string> found_vars;
  // Only do this on the first pass because variables declared later
  // in a script will get added to the outer scope, which these do not
  // reference e.g.
  // begin { @a[1] = 1; for ($kv : @a) { $x = 2; } let $x; }
  if (is_first_pass()) {
    // We save these for potential use at the end of this function in
    // subsequent passes in case the map we're iterating over isn't ready
    // yet and still needs additional passes to resolve its key/value types
    // e.g. begin { $x = 1; for ($kv : @a) { print(($x)); } @a[1] = 1; }
    //
    // This is especially tricky because we need to visit all statements
    // inside the for loop to get the types of the referenced variables but
    // only after we have the map's key/value type so we can also check
    // the usages of the created $kv tuple variable.
    auto [iter, _] = for_vars_referenced_.try_emplace(&f);
    auto &collector = iter->second;
    collector.visit(f.block, [this, &found_vars](const auto &var) {
      if (found_vars.contains(var.ident))
        return false;

      if (find_variable(var.ident)) {
        found_vars.insert(var.ident);
        return true;
      }
      return false;
    });
  }

  // Create type for the loop's decl.
  if (auto *map = f.iterable.as<Map>()) {
    // Iterating over a map provides a tuple: (map_key, map_val)
    auto *mapkey = get_map_key_type(*map);
    auto *mapval = get_map_type(*map);

    if (!mapkey || !mapval)
      return;

    f.decl->var_type = CreateTuple(Struct::CreateTuple({ *mapkey, *mapval }));
  } else if (auto *range = f.iterable.as<Range>()) {
    // Always use the same type as the first parameter.
    f.decl->var_type = range->start.type();
  }

  scope_stack_.push_back(&f);

  variables_[scope_stack_.back()][decl_name] = { .type = f.decl->type(),
                                                 .can_resize = true,
                                                 .was_assigned = true };

  loop_depth_++;
  visit(f.block);
  loop_depth_--;

  scope_stack_.pop_back();

  // Currently, we do not pass BPF context to the callback so disable builtins
  // which require ctx access.
  CollectNodes<Builtin> builtins;
  builtins.visit(f.block);
  for (const Builtin &builtin : builtins.nodes()) {
    if (builtin.builtin_type.IsCtxAccess() || builtin.is_argx() ||
        builtin.ident == "__builtin_retval") {
      builtin.addError() << "'" << builtin.ident
                         << "' builtin is not allowed in a for-loop";
    }
  }

  // Finally, create the context tuple now that all variables inside the loop
  // have been visited.
  std::vector<SizedType> ctx_types;
  std::vector<std::string_view> ctx_idents;
  auto [iter, _] = for_vars_referenced_.try_emplace(&f);
  auto &collector = iter->second;
  for (const Variable &var : collector.nodes()) {
    ctx_types.push_back(CreatePointer(var.var_type, AddrSpace::kernel));
    ctx_idents.push_back(var.ident);
  }
  f.ctx_type = CreateRecord(Struct::CreateRecord(ctx_types, ctx_idents));
}

void TypeGraphBuilder::visit(FieldAccess &acc)
{
  visit(acc.expr);
  const SizedType &type = acc.expr.type();

  if (type.IsPtrTy()) {
    acc.addError() << "Can not access field '" << acc.field << "' on type '"
                   << type << "'. Try dereferencing it first, or using '->'";
    return;
  }

  if (!type.IsRecordTy()) {
    if (is_final_pass()) {
      acc.addError() << "Can not access field '" << acc.field
                     << "' on expression of type '" << type << "'";
    }
    return;
  }

  if (type.is_funcarg) {
    auto *probe = get_probe(acc);
    if (probe == nullptr)
      return;
    const auto *arg = bpftrace_.structs.GetProbeArg(*probe, acc.field);
    if (arg) {
      acc.field_type = arg->type;
      acc.field_type.SetAS(acc.expr.type().GetAS());

      if (is_final_pass() && acc.field_type.IsNoneTy()) {
        acc.addError() << acc.field << " has unsupported type";
      }
    } else {
      acc.addError() << "Can't find function parameter " << acc.field;
    }
    return;
  }

  if (!bpftrace_.structs.Has(type.GetName())) {
    acc.addError() << "Unknown struct/union: '" << type.GetName() << "'";
    return;
  }

  std::map<std::string, std::shared_ptr<const Struct>> structs;

  if (type.is_tparg) {
    auto *probe = get_probe(acc);
    if (probe == nullptr)
      return;

    for (AttachPoint *attach_point : probe->attach_points) {
      if (probetype(attach_point->provider) != ProbeType::tracepoint) {
        // The args builtin can only be used with tracepoint
        // an error message is already generated in visit(Builtin)
        // just continue semantic analysis
        continue;
      }

      std::string tracepoint_struct = TracepointFormatParser::get_struct_name(
          *attach_point);
      structs[tracepoint_struct] =
          bpftrace_.structs.Lookup(tracepoint_struct).lock();
    }
  } else {
    structs[type.GetName()] = type.GetStruct();
  }

  for (auto it : structs) {
    std::string cast_type = it.first;
    const auto record = it.second;
    if (!record->HasField(acc.field)) {
      acc.addError() << "Struct/union of type '" << cast_type
                     << "' does not contain " << "a field named '" << acc.field
                     << "'";
    } else {
      const auto &field = record->GetField(acc.field);

      if (field.type.IsPtrTy()) {
        const auto &tags = field.type.GetBtfTypeTags();
        // Currently only "rcu" is safe. "percpu", for example, requires
        // special unwrapping with `bpf_per_cpu_ptr` which is not yet
        // supported.
        static const std::string_view allowed_tag = "rcu";
        for (const auto &tag : tags) {
          if (tag != allowed_tag) {
            acc.addError() << "Attempting to access pointer field '"
                           << acc.field
                           << "' with unsupported tag attribute: " << tag;
          }
        }
      }

      acc.field_type = field.type;
      if (acc.expr.type().IsCtxAccess() &&
          (acc.field_type.IsArrayTy() || acc.field_type.IsRecordTy())) {
        // e.g., ((struct bpf_perf_event_data*)ctx)->regs.ax
        acc.field_type.MarkCtxAccess();
      }
      acc.field_type.is_internal = type.is_internal;
      acc.field_type.SetAS(acc.expr.type().GetAS());

      // The kernel uses the first 8 bytes to store `struct pt_regs`. Any
      // access to the first 8 bytes results in verifier error.
      if (type.is_tparg && field.offset < 8)
        acc.addError()
            << "BPF does not support accessing common tracepoint fields";
    }
  }
}

void TypeGraphBuilder::visit(MapAccess &acc)
{
  visit(acc.map);
  visit(acc.key);
  reconcile_map_key(acc.map, acc.key);

  auto search_val = map_val_.find(acc.map->ident);
  if (search_val != map_val_.end()) {
    if (acc.map->type().IsCastableMapTy() &&
        !bpftrace_.feature_->has_helper_map_lookup_percpu_elem()) {
      acc.addError()
          << "Missing required kernel feature: map_lookup_percpu_elem";
    }
    acc.map->value_type = search_val->second;
  } else {
    // If there is no record of any assignment after the first pass
    // then it's safe to say this map is undefined.
    bool read_only = named_param_defaults_.defaults.contains(acc.map->ident);
    if (!is_first_pass() && !read_only) {
      acc.addError() << "Undefined map: " << acc.map->ident;
    }
    pass_tracker_.inc_num_unresolved();
  }
}

void TypeGraphBuilder::reconcile_map_key(Map *map, const Expression &key_expr)
{
  SizedType new_key_type = create_key_type(key_expr.type(), key_expr.node());

  if (const auto &key = map_key_.find(map->ident); key != map_key_.end()) {
    update_current_key(key->second, new_key_type);
    validate_new_key(key->second, new_key_type, map->ident, key_expr);
  } else {
    if (!new_key_type.IsNoneTy()) {
      map_key_.insert({ map->ident, new_key_type });
      map->key_type = new_key_type;
    }
  }
}

// We can't hint for unsigned types. It is a syntax error,
// because the word "unsigned" is not allowed in a type name.
static std::unordered_map<std::string_view, std::string_view>
    KNOWN_TYPE_ALIASES{
      { "char", "int8" },   /* { "unsigned char", "uint8" }, */
      { "short", "int16" }, /* { "unsigned short", "uint16" }, */
      { "int", "int32" },   /* { "unsigned int", "uint32" }, */
      { "long", "int64" },  /* { "unsigned long", "uint64" }, */
    };

void TypeGraphBuilder::visit(Cast &cast)
{
  visit(cast.expr);
  visit(cast.typeof);

  const auto &resolved_ty = cast.type();
  if (resolved_ty.IsNoneTy()) {
    pass_tracker_.inc_num_unresolved();
    if (is_final_pass()) {
      cast.addError() << "Incomplete cast, unknown type";
    }
    return; // Revisit next cycle.
  }

  auto rhs = cast.expr.type();
  if (rhs.IsRecordTy()) {
    cast.addError() << "Cannot cast from struct type \"" << cast.expr.type()
                    << "\"";
  } else if (rhs.IsNoneTy()) {
    if (is_final_pass()) {
      cast.addError() << "Cannot cast from \"" << cast.expr.type() << "\" type";
    } else {
      return; // Revisit later.
    }
  }

  // Resolved the type because we may mutate it below, for various reasons.
  cast.typeof->record = resolved_ty;
  auto &ty = std::get<SizedType>(cast.typeof->record);

  if (!ty.IsIntTy() && !ty.IsPtrTy() && !ty.IsBoolTy() &&
      (!ty.IsPtrTy() || ty.GetElementTy()->IsIntTy() ||
       ty.GetElementTy()->IsRecordTy()) &&
      // we support casting integers to int arrays
      !(ty.IsArrayTy() && ty.GetElementTy()->IsBoolTy()) &&
      !(ty.IsArrayTy() && ty.GetElementTy()->IsIntTy())) {
    auto &err = cast.addError();
    err << "Cannot cast to \"" << ty << "\"";
    if (auto it = KNOWN_TYPE_ALIASES.find(ty.GetName());
        it != KNOWN_TYPE_ALIASES.end()) {
      err.addHint() << "Did you mean \"" << it->second << "\"?";
    }
  }

  if (ty.IsArrayTy()) {
    if (ty.GetNumElements() == 0) {
      if (ty.GetElementTy()->GetSize() == 0)
        cast.addError() << "Could not determine size of the array";
      else {
        if (rhs.GetSize() % ty.GetElementTy()->GetSize() != 0) {
          cast.addError() << "Cannot determine array size: the element size is "
                             "incompatible with the cast integer size";
        }

        // cast to unsized array (e.g. int8[]), determine size from RHS
        auto num_elems = rhs.GetSize() / ty.GetElementTy()->GetSize();
        ty = CreateArray(num_elems, *ty.GetElementTy());
      }
    }

    if (rhs.IsIntTy() || rhs.IsBoolTy())
      ty.is_internal = true;
  }

  if (ty.IsEnumTy()) {
    if (!c_definitions_.enum_defs.contains(ty.GetName())) {
      cast.addError() << "Unknown enum: " << ty.GetName();
    } else {
      if (auto *integer = cast.expr.as<Integer>()) {
        if (!c_definitions_.enum_defs[ty.GetName()].contains(integer->value)) {
          cast.addError() << "Enum: " << ty.GetName()
                          << " doesn't contain a variant value of "
                          << integer->value;
        }
      }
    }
  }

  if (ty.IsBoolTy() && !rhs.IsIntTy() && !rhs.IsStringTy() && !rhs.IsPtrTy() &&
      !rhs.IsCastableMapTy()) {
    if (is_final_pass()) {
      cast.addError() << "Cannot cast from \"" << rhs << "\" to \"" << ty
                      << "\"";
    }
  }

  if ((ty.IsIntTy() && !rhs.IsIntTy() && !rhs.IsPtrTy() && !rhs.IsBoolTy() &&
       !rhs.IsCtxAccess() && !rhs.IsArrayTy() && !rhs.IsCastableMapTy()) ||
      // casting from/to int arrays must respect the size
      (ty.IsArrayTy() && (!rhs.IsBoolTy() || ty.GetSize() != rhs.GetSize()) &&
       (!rhs.IsIntTy() || ty.GetSize() != rhs.GetSize())) ||
      (rhs.IsArrayTy() && (!ty.IsIntTy() || ty.GetSize() != rhs.GetSize()))) {
    cast.addError() << "Cannot cast from \"" << rhs << "\" to \"" << ty << "\"";
  }

  if (cast.expr.type().IsCtxAccess() && !ty.IsIntTy()) {
    ty.MarkCtxAccess();
  }
  ty.SetAS(cast.expr.type().GetAS());
  // case : begin { @foo = (struct Foo)0; }
  // case : profile:hz:99 $task = (struct task_struct *)curtask.
  if (ty.GetAS() == AddrSpace::none) {
    if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
      ProbeType type = single_provider_type(probe);
      ty.SetAS(find_addrspace(type));
    } else {
      // Assume kernel space for data in subprogs.
      ty.SetAS(AddrSpace::kernel);
    }
  }
}

void TypeGraphBuilder::visit(Tuple &tuple)
{
  std::vector<SizedType> elements;
  for (auto &elem : tuple.elems) {
    visit(elem);

    // If elem type is none that means that the tuple contains some
    // invalid cast (e.g., (0, (aaa)0)). In this case, skip the tuple
    // creation. Cast already emits the error.
    if (elem.type().IsNoneTy() || elem.type().GetSize() == 0) {
      return;
    } else if (elem.type().IsMultiKeyMapTy()) {
      elem.node().addError()
          << "Map type " << elem.type() << " cannot exist inside a tuple.";
    }
    elements.emplace_back(elem.type());
  }

  tuple.tuple_type = CreateTuple(Struct::CreateTuple(elements));
}

void TypeGraphBuilder::visit(Expression &expr)
{
  // Visit and fold all other values.
  Visitor<TypeGraphBuilder>::visit(expr);
  fold(ctx_, expr);

  // Inline specific constant expressions.
  if (auto *szof = expr.as<Sizeof>()) {
    const auto v = check(*szof);
    if (v) {
      expr.value = ctx_.make_node<Integer>(*v,
                                           Location(szof->loc),
                                           /*force_unsigned=*/true);
    }
  } else if (auto *offof = expr.as<Offsetof>()) {
    const auto v = check(*offof);
    if (v) {
      expr.value = ctx_.make_node<Integer>(*v,
                                           Location(offof->loc),
                                           /*force_unsigned=*/true);
    }
  }
}

void TypeGraphBuilder::visit(ExprStatement &expr)
{
  if (auto *call = expr.expr.as<Call>()) {
    // Calls from expression statements are bare, meaning they're not
    // handling the return value e.g.
    // delete(@a, 1); <- ExprStatement
    // vs
    // $x = delete(@a, 1) <- AssignVarStatement
    // if (delete(@a, 1)) { <- If
    call->ret_val_discarded = true;
  }

  visit(expr.expr);
}

static const std::unordered_map<Type, std::string_view> AGGREGATE_HINTS{
  { Type::count_t, "count()" },
  { Type::sum_t, "sum(retval)" },
  { Type::min_t, "min(retval)" },
  { Type::max_t, "max(retval)" },
  { Type::avg_t, "avg(retval)" },
  { Type::hist_t, "hist(retval)" },
  { Type::lhist_t, "lhist(rand %10, 0, 10, 1)" },
  { Type::tseries_t, "tseries(rand %10, 10s, 1)" },
  { Type::stats_t, "stats(arg2)" },
};

void TypeGraphBuilder::visit(AssignMapStatement &assignment)
{
  visit(assignment.map);
  visit(assignment.key);
  visit(assignment.expr);

  reconcile_map_key(assignment.map, assignment.key);
  const auto *map_type_before = get_map_type(*assignment.map);

  // Add an implicit cast when copying the value of an aggregate map to an
  // existing map of int. Enables the following: `@x = 1; @y = count(); @x =
  // @y`
  const bool map_contains_int = map_type_before && map_type_before->IsIntTy();
  if (map_contains_int && assignment.expr.type().IsCastableMapTy()) {
    auto *typeof = ctx_.make_node<Typeof>(*map_type_before,
                                          Location(assignment.loc));
    assignment.expr = ctx_.make_node<Cast>(typeof,
                                           assignment.expr,
                                           Location(assignment.loc));
  }

  if (!is_valid_assignment(assignment.expr, map_type_before == nullptr)) {
    auto &err = assignment.addError();
    const auto &type = assignment.expr.type();
    auto hint = AGGREGATE_HINTS.find(type.GetTy());
    if (hint == AGGREGATE_HINTS.end()) {
      err << "Not a valid assignment: " << type.GetTy();
    } else {
      err << "Map value '" << type
          << "' cannot be assigned from one map to another. "
             "The function that returns this type must be called directly "
             "e.g. "
             "`"
          << assignment.map->ident << " = " << hint->second << ";`.";

      if (const auto *acc = assignment.expr.as<MapAccess>()) {
        if (type.IsCastableMapTy()) {
          err.addHint() << "Add a cast to integer if you want the value of the "
                           "aggregate, "
                        << "e.g. `" << assignment.map->ident << " = (int64)"
                        << acc->map->ident << ";`.";
        }
      }
    }
  }

  assign_map_type(
      *assignment.map, assignment.expr.type(), &assignment, &assignment);

  const auto &map_ident = assignment.map->ident;
  const auto &type = assignment.expr.type();

  if (type.IsRecordTy() && map_val_[map_ident].IsRecordTy()) {
    std::string ty = assignment.expr.type().GetName();
    std::string stored_ty = map_val_[map_ident].GetName();
    if (!stored_ty.empty() && stored_ty != ty) {
      assignment.addError() << "Type mismatch for " << map_ident << ": "
                            << "trying to assign value of type '" << ty
                            << "' when map already contains a value of type '"
                            << stored_ty << "'";
    } else {
      map_val_[map_ident] = assignment.expr.type();
      map_val_[map_ident].is_internal = true;
    }
  } else if (type.IsStringTy()) {
    auto map_size = map_val_[map_ident].GetSize();
    auto expr_size = assignment.expr.type().GetSize();
    if (map_size < expr_size) {
      assignment.addWarning() << "String size mismatch: " << map_size << " < "
                              << expr_size << ". The value may be truncated.";
    }
  } else if (type.IsBufferTy()) {
    auto map_size = map_val_[map_ident].GetSize();
    auto expr_size = assignment.expr.type().GetSize();
    if (map_size != expr_size) {
      std::stringstream buf;
      buf << "Buffer size mismatch: " << map_size << " != " << expr_size << ".";
      if (map_size < expr_size) {
        buf << " The value may be truncated.";
        assignment.addWarning() << buf.str();
      } else {
        // bpf_map_update_elem() expects map_size-length value
        assignment.addError() << buf.str();
      }
    }
  } else if (type.IsCtxAccess()) {
    // bpf_map_update_elem() only accepts a pointer to a element in the stack
    assignment.addError() << "context cannot be assigned to a map";
  } else if (type.IsTupleTy()) {
    // Early passes may not have been able to deduce the full types of tuple
    // elements yet. So wait until final pass.
    if (is_final_pass()) {
      const auto &map_type = map_val_[map_ident];
      const auto &expr_type = assignment.expr.type();
      if (!expr_type.FitsInto(map_type)) {
        assignment.addError() << "Tuple type mismatch: " << map_type
                              << " != " << expr_type << ".";
      }
    }
  } else if (type.IsArrayTy()) {
    const auto &map_type = map_val_[map_ident];
    const auto &expr_type = assignment.expr.type();
    if (map_type == expr_type) {
      map_val_[map_ident].is_internal = true;
    } else {
      assignment.addError()
          << "Array type mismatch: " << map_type << " != " << expr_type << ".";
    }
  } else if (type.IsNoneTy()) {
    pass_tracker_.inc_num_unresolved();
  }
}

void TypeGraphBuilder::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);

  // Only visit the declaration if it is a `let` declaration,
  // otherwise skip as it is not a variable access.
  if (std::holds_alternative<VarDeclStatement *>(assignment.var_decl)) {
    visit(assignment.var_decl);
  }

  if (assignment.expr.type().IsCastableMapTy()) {
    auto *typeof = ctx_.make_node<Typeof>(CreateInt64(),
                                          Location(assignment.loc));
    assignment.expr = ctx_.make_node<Cast>(typeof,
                                           assignment.expr,
                                           Location(assignment.loc));
  }

  if (!is_valid_assignment(assignment.expr, false)) {
    if (is_final_pass()) {
      assignment.addError() << "Value '" << assignment.expr.type()
                            << "' cannot be assigned to a scratch variable.";
    }
    return;
  }

  Node *var_scope = nullptr;
  const auto &var_ident = assignment.var()->ident;
  auto assignTy = assignment.expr.type();

  if (auto *scope = find_variable_scope(var_ident)) {
    auto &foundVar = variables_[scope][var_ident];
    auto &storedTy = foundVar.type;
    bool type_mismatch_error = false;
    if (storedTy.IsNoneTy()) {
      storedTy = assignTy;
    } else if (!storedTy.IsSameType(assignTy) &&
               (!storedTy.IsIntegerTy() || !assignTy.IsIntegerTy())) {
      if (!assignTy.IsNoneTy() || is_final_pass()) {
        type_mismatch_error = true;
      } else {
        pass_tracker_.inc_num_unresolved();
      }
    } else if (assignTy.IsStringTy()) {
      if (foundVar.can_resize) {
        update_string_size(storedTy, assignTy);
      } else if (!assignTy.FitsInto(storedTy)) {
        type_mismatch_error = true;
      }
    } else if (storedTy.IsIntegerTy()) {
      if (storedTy.IsEqual(assignTy)) {
        // No checks or casts needed.
      } else if (auto *neg_integer = assignment.expr.as<NegativeInteger>()) {
        int64_t value = neg_integer->value;
        if (!storedTy.IsSigned()) {
          type_mismatch_error = true;
        } else {
          auto min_max = getIntTypeRange(storedTy);
          if (value < min_max.first) {
            assignment.addError()
                << "Type mismatch for " << var_ident << ": "
                << "trying to assign value '" << neg_integer->value
                << "' which does not fit into the variable of type '"
                << storedTy << "'";
          } else {
            assignTy = storedTy;
            auto *typeof = ctx_.make_node<Typeof>(
                CreateInteger(storedTy.GetSize() * 8, true),
                Location(assignment.loc));
            assignment.expr = ctx_.make_node<Cast>(typeof,
                                                   assignment.expr,
                                                   Location(assignment.loc));
            visit(assignment.expr);
          }
        }
      } else if (auto *integer = assignment.expr.as<Integer>()) {
        uint64_t value = integer->value;
        bool can_fit = false;
        if (!storedTy.IsSigned()) {
          auto min_max = getUIntTypeRange(storedTy);
          can_fit = value <= min_max.second;
        } else {
          auto min_max = getIntTypeRange(storedTy);
          can_fit = value <= static_cast<uint64_t>(min_max.second);
        }
        if (can_fit) {
          assignTy = storedTy;
          auto *typeof = ctx_.make_node<Typeof>(
              CreateInteger(storedTy.GetSize() * 8, storedTy.IsSigned()),
              Location(assignment.loc));
          assignment.expr = ctx_.make_node<Cast>(typeof,
                                                 assignment.expr,
                                                 Location(assignment.loc));
          visit(assignment.expr);
        } else {
          assignment.addError()
              << "Type mismatch for " << var_ident << ": "
              << "trying to assign value '"
              << static_cast<uint64_t>(integer->value)
              << "' which does not fit into the variable of type '" << storedTy
              << "'";
        }
      } else if (storedTy.IsSigned() != assignTy.IsSigned()) {
        type_mismatch_error = true;
      } else {
        if (!assignTy.FitsInto(storedTy)) {
          assignment.addError()
              << "Integer size mismatch. Assignment type '" << assignTy
              << "' is larger than the variable type '" << storedTy << "'.";
        }
      }
    } else if (assignTy.IsBufferTy()) {
      auto var_size = storedTy.GetSize();
      auto expr_size = assignTy.GetSize();
      if (var_size != expr_size) {
        assignment.addWarning()
            << "Buffer size mismatch: " << var_size << " != " << expr_size
            << (var_size < expr_size ? ". The value may be truncated."
                                     : ". The value may contain garbage.");
      }
    } else if (assignTy.IsTupleTy()) {
      update_string_size(storedTy, assignTy);
      // Early passes may not have been able to deduce the full types of tuple
      // elements yet. So wait until final pass.
      if (is_final_pass()) {
        if (!assignTy.FitsInto(storedTy)) {
          type_mismatch_error = true;
        }
      }
    }
    if (type_mismatch_error) {
      const auto *err_segment =
          foundVar.was_assigned
              ? "when variable already contains a value of type"
              : "when variable already has a type";
      assignment.addError() << "Type mismatch for " << var_ident << ": "
                            << "trying to assign value of type '" << assignTy
                            << "' " << err_segment << " '" << storedTy << "'";
    } else {
      if (!foundVar.was_assigned) {
        // The assign type is possibly more complete than the stored type,
        // which could come from a variable declaration. The assign type may
        // resolve builtins like `curtask` which also specifies the address
        // space.
        foundVar.type = assignTy;
        foundVar.was_assigned = true;
      }
      var_scope = scope;
    }
  }

  if (var_scope == nullptr) {
    variables_[scope_stack_.back()].insert(
        { var_ident,
          { .type = assignTy, .can_resize = true, .was_assigned = true } });
    var_scope = scope_stack_.back();
  }

  const auto &storedTy = variables_[var_scope][var_ident].type;
  assignment.var()->var_type = storedTy;

  if (is_final_pass()) {
    if (storedTy.IsNoneTy())
      assignment.addError()
          << "Invalid expression for assignment: " << storedTy;
  }
}

void TypeGraphBuilder::visit(VarDeclStatement &decl)
{
  visit(decl.typeof);
  const std::string &var_ident = decl.var->ident;

  if (decl.typeof) {
    const auto &ty = decl.typeof->type();
    if (!ty.IsNoneTy()) {
      if (!IsValidVarDeclType(ty)) {
        decl.addError() << "Invalid variable declaration type: " << ty;
      } else {
        decl.var->var_type = ty;
      }
    } else if (is_final_pass()) {
      // We couldn't resolve that specific type by now.
      decl.addError() << "Type cannot be resolved: still none";
    }
  }

  // Only checking on the first pass for cases like this:
  // `begin { if (1) { let $x; } else { let $x; } let $x; }`
  // Notice how the last `let $x` is defined in the outer scope;
  // this means on subsequent passes the first two `let $x` statements
  // would be considered variable shadowing, when in fact, because of order,
  // there is no ambiguity in terms of future assignment and use.
  if (is_first_pass()) {
    for (auto *scope : scope_stack_) {
      // This should be the first time we're seeing this variable
      if (auto decl_search = variable_decls_[scope].find(var_ident);
          decl_search != variable_decls_[scope].end()) {
        if (&decl_search->second != &decl) {
          decl.addError()
              << "Variable " << var_ident
              << " was already declared. Variable shadowing is not allowed.";
          decl_search->second.addWarning()
              << "This is the initial declaration.";
        }
      }
    }
  }

  if (is_first_pass() || is_final_pass()) {
    if (auto *scope = find_variable_scope(var_ident)) {
      auto &foundVar = variables_[scope][var_ident];
      // Checking the first pass only for cases like this:
      // `begin { if (1) { let $x; } $x = 2; }`
      // Again, this is legal and there is no ambiguity but `$x = 2` gets
      // placed in the outer scope so subsequent passes would consider
      // this a use before declaration error (below)
      if (!variable_decls_[scope].contains(var_ident) && is_first_pass()) {
        decl.addError()
            << "Variable declarations need to occur before variable usage or "
               "assignment. Variable: "
            << var_ident;
      } else if (is_final_pass()) {
        // Update the declaration type if it was either not set e.g. `let $a;`
        // or the type is ambiguous or resizable e.g. `let $a: string;`
        decl.var->var_type = foundVar.type;
      }

      if (is_final_pass() && !foundVar.was_assigned) {
        decl.addWarning() << "Variable " << var_ident << " never assigned to.";
      }

      return;
    }
  }

  bool can_resize = decl.var->var_type.GetSize() == 0;

  variables_[scope_stack_.back()].insert({ var_ident,
                                           { .type = decl.var->var_type,
                                             .can_resize = can_resize,
                                             .was_assigned = false } });
  variable_decls_[scope_stack_.back()].insert({ var_ident, decl });
}

void TypeGraphBuilder::visit(AttachPoint &ap)
{
  if (ap.provider == "kprobe" || ap.provider == "kretprobe") {
    if (ap.func.empty())
      ap.addError() << "kprobes should be attached to a function";
    if (is_final_pass()) {
      // Warn if user tries to attach to a non-traceable function
      if (bpftrace_.config_->missing_probes != ConfigMissingProbes::ignore &&
          !util::has_wildcard(ap.func) &&
          !bpftrace_.is_traceable_func(ap.func)) {
        ap.addWarning() << ap.func
                        << " is not traceable (either non-existing, inlined, "
                           "or marked as "
                           "\"notrace\"); attaching to it will likely fail";
      }
    }
  } else if (ap.provider == "uprobe" || ap.provider == "uretprobe") {
    if (ap.target.empty())
      ap.addError() << ap.provider << " should have a target";
    if (ap.func.empty() && ap.address == 0)
      ap.addError() << ap.provider
                    << " should be attached to a function and/or address";
    if (!ap.lang.empty() && !is_supported_lang(ap.lang))
      ap.addError() << "unsupported language type: " << ap.lang;

    if (ap.provider == "uretprobe" && ap.func_offset != 0)
      ap.addError() << "uretprobes can not be attached to a function offset";

    auto get_paths = [&]() -> Result<std::vector<std::string>> {
      const auto pid = bpftrace_.pid();
      if (ap.target == "*") {
        if (pid.has_value())
          return util::get_mapped_paths_for_pid(*pid);
        else
          return util::get_mapped_paths_for_running_pids();
      } else {
        return util::resolve_binary_path(ap.target, pid);
      }
    };
    auto paths = get_paths();
    if (!paths) {
      // There was an error during path resolution.
      ap.addError() << "error finding uprobe target: " << paths.takeError();
    } else {
      switch (paths->size()) {
        case 0:
          ap.addError() << "uprobe target file '" << ap.target
                        << "' does not exist or is not executable";
          break;
        case 1:
          // Replace the glob at this stage only if this is *not* a wildcard,
          // otherwise we rely on the probe matcher. This is not going through
          // any interfaces that can be properly mocked.
          if (ap.target.find("*") == std::string::npos)
            ap.target = paths->front();
          break;
        default:
          // If we are doing a PATH lookup (ie not glob), we follow shell
          // behavior and take the first match.
          // Otherwise we keep the target with glob, it will be expanded later
          if (ap.target.find("*") == std::string::npos) {
            ap.addWarning() << "attaching to uprobe target file '"
                            << paths->front() << "' but matched "
                            << std::to_string(paths->size()) << " binaries";
            ap.target = paths->front();
          }
      }
    }
  } else if (ap.provider == "usdt") {
    bpftrace_.has_usdt_ = true;
    if (ap.func.empty())
      ap.addError() << "usdt probe must have a target function or wildcard";

    if (!ap.target.empty() &&
        !(bpftrace_.pid().has_value() && util::has_wildcard(ap.target))) {
      auto paths = util::resolve_binary_path(ap.target, bpftrace_.pid());
      switch (paths.size()) {
        case 0:
          ap.addError() << "usdt target file '" << ap.target
                        << "' does not exist or is not executable";
          break;
        case 1:
          // See uprobe, above.
          if (ap.target.find("*") == std::string::npos)
            ap.target = paths.front();
          break;
        default:
          // See uprobe, above.
          if (ap.target.find("*") == std::string::npos) {
            ap.addWarning() << "attaching to usdt target file '"
                            << paths.front() << "' but matched "
                            << std::to_string(paths.size()) << " binaries";
            ap.target = paths.front();
          }
      }
    }

    const auto pid = bpftrace_.pid();
    if (pid.has_value()) {
      USDTHelper::probes_for_pid(*pid);
    } else if (ap.target == "*") {
      USDTHelper::probes_for_all_pids();
    } else if (!ap.target.empty()) {
      for (auto &path : util::resolve_binary_path(ap.target))
        USDTHelper::probes_for_path(path);
    } else {
      ap.addError() << "usdt probe must specify at least path or pid to "
                       "probe. To target "
                       "all paths/pids set the path to '*'.";
    }
  } else if (ap.provider == "tracepoint") {
    if (ap.target.empty() || ap.func.empty())
      ap.addError() << "tracepoint probe must have a target";
  } else if (ap.provider == "rawtracepoint") {
    if (ap.func.empty())
      ap.addError() << "rawtracepoint should be attached to a function";

    if (!listing_ && !bpftrace_.has_btf_data()) {
      ap.addError() << "rawtracepoints require kernel BTF. Try using a "
                       "'tracepoint' instead.";
    }

  } else if (ap.provider == "profile") {
    if (ap.target.empty())
      ap.addError() << "profile probe must have unit of time";
    else if (!listing_) {
      if (!TIME_UNITS.contains(ap.target))
        ap.addError() << ap.target << " is not an accepted unit of time";
      if (!ap.func.empty())
        ap.addError() << "profile probe must have an integer frequency";
      else if (ap.freq <= 0)
        ap.addError() << "profile frequency should be a positive integer";
    }
  } else if (ap.provider == "interval") {
    if (ap.target.empty())
      ap.addError() << "interval probe must have unit of time";
    else if (!listing_) {
      if (!TIME_UNITS.contains(ap.target))
        ap.addError() << ap.target << " is not an accepted unit of time";
      if (!ap.func.empty())
        ap.addError() << "interval probe must have an integer frequency";
      else if (ap.freq <= 0)
        ap.addError() << "interval frequency should be a positive integer";
    }
  } else if (ap.provider == "software") {
    if (ap.target.empty())
      ap.addError() << "software probe must have a software event name";
    else {
      if (!util::has_wildcard(ap.target) && !ap.ignore_invalid) {
        bool found = false;
        for (const auto &probeListItem : SW_PROBE_LIST) {
          if (ap.target == probeListItem.path ||
              (!probeListItem.alias.empty() &&
               ap.target == probeListItem.alias)) {
            found = true;
            break;
          }
        }
        if (!found)
          ap.addError() << ap.target << " is not a software probe";
      } else if (!listing_) {
        ap.addError() << "wildcards are not allowed for hardware probe type";
      }
    }
    if (!ap.func.empty())
      ap.addError() << "software probe can only have an integer count";
    else if (ap.freq < 0)
      ap.addError() << "software count should be a positive integer";
  } else if (ap.provider == "watchpoint" || ap.provider == "asyncwatchpoint") {
    if (!ap.func.empty()) {
      if (!bpftrace_.pid().has_value() && !has_child_)
        ap.addError() << "-p PID or -c CMD required for watchpoint";

      if (ap.address >= static_cast<uint64_t>(arch::Host::arguments().size()))
        ap.addError() << arch::Host::Machine << " doesn't support arg"
                      << ap.address;
    } else if (ap.provider == "asyncwatchpoint")
      ap.addError() << ap.provider << " requires a function name";
    else if (!ap.address)
      ap.addError() << "watchpoint must be attached to a non-zero address";
    if (ap.len != 1 && ap.len != 2 && ap.len != 4 && ap.len != 8)
      ap.addError() << "watchpoint length must be one of (1,2,4,8)";
    if (ap.mode.empty())
      ap.addError() << "watchpoint mode must be combination of (r,w,x)";
    std::ranges::sort(ap.mode);
    for (const char c : ap.mode) {
      if (c != 'r' && c != 'w' && c != 'x')
        ap.addError() << "watchpoint mode must be combination of (r,w,x)";
    }
    for (size_t i = 1; i < ap.mode.size(); ++i) {
      if (ap.mode[i - 1] == ap.mode[i])
        ap.addError() << "watchpoint modes may not be duplicated";
    }
    const auto &modes = arch::Host::watchpoint_modes();
    if (!modes.contains(ap.mode)) {
      if (modes.empty()) {
        // There are no valid modes.
        ap.addError() << "watchpoints not supported";
      } else {
        // Build a suitable error with hint.
        auto &err = ap.addError();
        err << "invalid watchpoint mode: " << ap.mode;
        err.addHint() << "supported modes: "
                      << util::str_join(std::vector(modes.begin(), modes.end()),
                                        ",");
      }
    }
  } else if (ap.provider == "hardware") {
    if (ap.target.empty())
      ap.addError() << "hardware probe must have a hardware event name";
    else {
      if (!util::has_wildcard(ap.target) && !ap.ignore_invalid) {
        bool found = false;
        for (const auto &probeListItem : HW_PROBE_LIST) {
          if (ap.target == probeListItem.path ||
              (!probeListItem.alias.empty() &&
               ap.target == probeListItem.alias)) {
            found = true;
            break;
          }
        }
        if (!found)
          ap.addError() << ap.target + " is not a hardware probe";
      } else if (!listing_) {
        ap.addError() << "wildcards are not allowed for hardware probe type";
      }
    }
    if (!ap.func.empty())
      ap.addError() << "hardware probe can only have an integer count";
    else if (ap.freq < 0)
      ap.addError() << "hardware frequency should be a positive integer";
  } else if (ap.provider == "begin" || ap.provider == "end") {
    if (!ap.target.empty() || !ap.func.empty())
      ap.addError() << "begin/end probes should not have a target";
    if (is_final_pass()) {
      if (ap.provider == "begin") {
        if (has_begin_probe_)
          ap.addError() << "More than one begin probe defined";
        has_begin_probe_ = true;
      }
      if (ap.provider == "end") {
        if (has_end_probe_)
          ap.addError() << "More than one end probe defined";
        has_end_probe_ = true;
      }
    }
  } else if (ap.provider == "self") {
    if (ap.target == "signal") {
      if (!SIGNALS.contains(ap.func))
        ap.addError() << ap.func << " is not a supported signal";
      return;
    }
    ap.addError() << ap.target << " is not a supported trigger";
  } else if (ap.provider == "bench") {
    if (ap.target.empty())
      ap.addError() << "bench probes must have a name";
    if (is_final_pass()) {
      auto it = benchmark_locs_.find(ap.target);

      if (it != benchmark_locs_.end()) {
        auto &err = ap.addError();
        err << "\"" + ap.target + "\""
            << " was used as the name for more than one BENCH probe";
        err.addContext(it->second) << "this is the other instance";
      }

      benchmark_locs_.emplace(ap.target, ap.loc);
    }
  } else if (ap.provider == "fentry" || ap.provider == "fexit") {
    if (!bpftrace_.feature_->has_fentry()) {
      ap.addError() << "fentry/fexit not available for your kernel version.";
      return;
    }

    if (ap.func.empty())
      ap.addError() << "fentry/fexit should specify a function";
  } else if (ap.provider == "iter") {
    if (!listing_ && !bpftrace_.btf_->get_all_iters().contains(ap.func)) {
      ap.addError() << "iter " << ap.func
                    << " not available for your kernel version.";
    }

    if (ap.func.empty())
      ap.addError() << "iter should specify a iterator's name";
  } else {
    ap.addError() << "Invalid provider: '" << ap.provider << "'";
  }
}

void TypeGraphBuilder::visit(BlockExpr &block)
{
  scope_stack_.push_back(&block);
  for (size_t i = 0; i < block.stmts.size(); i++) {
    auto &stmt = block.stmts.at(i);
    visit(stmt);
    if (is_final_pass()) {
      auto *jump = stmt.as<Jump>();
      if (jump && i < (block.stmts.size() - 1)) {
        jump->addWarning() << "All code after a '" << opstr(*jump)
                           << "' is unreachable.";
      }
    }
  }
  visit(block.expr);
  scope_stack_.pop_back();
}

void TypeGraphBuilder::visit(Probe &probe)
{
  auto aps = probe.attach_points.size();
  top_level_node_ = &probe;

  for (AttachPoint *ap : probe.attach_points) {
    if (!listing_ && aps > 1 && ap->provider == "iter") {
      if (util::has_wildcard(ap->raw_input))
        ap->addError() << "iter probe type does not support wildcards";
      else
        ap->addError() << "Only single iter attach point is allowed.";
      return;
    }
    visit(ap);
  }
  visit(probe.block);
}

void TypeGraphBuilder::visit(Subprog &subprog)
{
  // Note that we visit the subprogram and process arguments *after*
  // constructing the stack with the variable states. This is because the
  // arguments, etc. may have types defined in terms of the arguments
  // themselves. We already handle detecting circular dependencies.
  scope_stack_.push_back(&subprog);
  top_level_node_ = &subprog;
  for (SubprogArg *arg : subprog.args) {
    const auto &ty = arg->typeof->type();
    auto &var = variables_[scope_stack_.back()]
                    .emplace(arg->var->ident,
                             variable{ .type = ty,
                                       .can_resize = true,
                                       .was_assigned = true })
                    .first->second;
    var.type = ty; // Override in case it has changed.
  }

  // Validate that arguments are set.
  visit(subprog.args);
  for (SubprogArg *arg : subprog.args) {
    if (arg->typeof->type().IsNoneTy()) {
      pass_tracker_.inc_num_unresolved();
      if (is_final_pass()) {
        arg->addError() << "Unable to resolve argument type.";
      }
    }
  }

  // Visit all statements.
  visit(subprog.block);

  // Validate that the return type is valid.
  visit(subprog.return_type);
  if (subprog.return_type->type().IsNoneTy()) {
    pass_tracker_.inc_num_unresolved();
    if (is_final_pass()) {
      subprog.return_type->addError()
          << "Unable to resolve suitable return type.";
    }
  }
  scope_stack_.pop_back();
}

int TypeGraphBuilder::analyse()
{
  std::string errors;

  int last_num_unresolved = 0;
  // Multiple passes to handle variables being used before they are defined
  while (ctx_.diagnostics().ok()) {
    pass_tracker_.reset_num_unresolved();

    visit(ctx_.root);

    if (is_final_pass()) {
      return pass_tracker_.get_num_passes();
    }

    int num_unresolved = pass_tracker_.get_num_unresolved();

    if (num_unresolved > 0 &&
        (last_num_unresolved == 0 || num_unresolved < last_num_unresolved)) {
      // If we're making progress, keep making passes
      last_num_unresolved = num_unresolved;
    } else {
      pass_tracker_.mark_final_pass();
    }

    pass_tracker_.inc_num_passes();
  }

  return 1;
}

inline bool TypeGraphBuilder::is_final_pass() const
{
  return pass_tracker_.is_final_pass();
}

bool TypeGraphBuilder::is_first_pass() const
{
  return pass_tracker_.get_num_passes() == 1;
}

bool TypeGraphBuilder::check_arg(const Call &call,
                                 size_t index,
                                 const arg_type_spec &spec)
{
  if (spec.skip_check) {
    return true;
  }
  return check_arg(call, spec.type, index, spec.literal);
}

bool TypeGraphBuilder::check_arg(const Call &call,
                                 size_t index,
                                 const map_type_spec &spec)
{
  if (auto *map = call.vargs.at(index).as<Map>()) {
    if (spec.type) {
      SizedType type = spec.type(call);
      assign_map_type(*map, type, &call);
    }
    if (is_final_pass() && map->type().IsNoneTy()) {
      map->addError() << "Undefined map: " + map->ident;
    }
    return true;
  }
  call.vargs.at(index).node().addError()
      << call.func << "() expects a map argument";
  return false;
}

bool TypeGraphBuilder::check_arg(const Call &call,
                                 size_t index,
                                 const map_key_spec &spec)
{
  if (auto *map = call.vargs.at(spec.map_index).as<Map>()) {
    // This reconciles the argument if the other one is a map, but otherwise
    // we don't specifically emit an error. `map_type_spec` above does that.
    reconcile_map_key(map, call.vargs.at(index));
    return true;
  } else {
    return false;
  }
}

bool TypeGraphBuilder::check_call(const Call &call)
{
  auto spec = CALL_SPEC.find(call.func);
  if (spec == CALL_SPEC.end()) {
    return true;
  }

  if (is_final_pass() && call.ret_val_discarded &&
      spec->second.discard_ret_warn) {
    call.addWarning() << "Return value discarded for " << call.func
                      << ". It should be used.";
  }

  auto ret = true;
  if (spec->second.min_args != spec->second.max_args) {
    ret = check_varargs(call, spec->second.min_args, spec->second.max_args);
  } else {
    ret = check_nargs(call, spec->second.min_args);
  }

  if (!ret) {
    return ret;
  }

  for (size_t i = 0; i < spec->second.arg_types.size() && i < call.vargs.size();
       ++i) {
    std::visit([&](const auto &v) { ret = ret && check_arg(call, i, v); },
               spec->second.arg_types.at(i));
  }

  return ret;
}

// Checks the number of arguments passed to a function is correct.
bool TypeGraphBuilder::check_nargs(const Call &call, size_t expected_nargs)
{
  std::stringstream err;
  auto nargs = call.vargs.size();
  assert(nargs >= call.injected_args);
  assert(expected_nargs >= call.injected_args);
  nargs -= call.injected_args;
  expected_nargs -= call.injected_args;

  if (nargs != expected_nargs) {
    if (expected_nargs == 0)
      err << call.func << "() requires no arguments";
    else if (expected_nargs == 1)
      err << call.func << "() requires one argument";
    else
      err << call.func << "() requires " << expected_nargs << " arguments";

    err << " (" << nargs << " provided)";
    call.addError() << err.str();
    return false;
  }
  return true;
}

// Checks the number of arguments passed to a function is within a specified
// range.
bool TypeGraphBuilder::check_varargs(const Call &call,
                                     size_t min_nargs,
                                     size_t max_nargs)
{
  std::stringstream err;
  auto nargs = call.vargs.size();
  assert(nargs >= call.injected_args);
  assert(min_nargs >= call.injected_args);
  assert(max_nargs >= call.injected_args);
  nargs -= call.injected_args;
  min_nargs -= call.injected_args;
  max_nargs -= call.injected_args;

  if (nargs < min_nargs) {
    if (min_nargs == 1)
      err << call.func << "() requires at least one argument";
    else
      err << call.func << "() requires at least " << min_nargs << " arguments";

    err << " (" << nargs << " provided)";
    call.addError() << err.str();
    return false;
  } else if (nargs > max_nargs) {
    if (max_nargs == 0)
      err << call.func << "() requires no arguments";
    else if (max_nargs == 1)
      err << call.func << "() takes up to one argument";
    else
      err << call.func << "() takes up to " << max_nargs << " arguments";

    err << " (" << nargs << " provided)";
    call.addError() << err.str();
    return false;
  }

  return true;
}

// Checks an argument passed to a function is of the correct type.
//
// This function does not check that the function has the correct number of
// arguments. Either check_nargs() or check_varargs() should be called first
// to validate this.
bool TypeGraphBuilder::check_arg(const Call &call,
                                 Type type,
                                 size_t index,
                                 bool want_literal)
{
  const auto &arg = call.vargs.at(index);
  bool is_literal = arg.is<Integer>() || arg.is<NegativeInteger>() ||
                    arg.is<String>();

  if (want_literal && (!is_literal || arg.type().GetTy() != type)) {
    call.addError() << call.func << "() expects a " << type << " literal ("
                    << arg.type().GetTy() << " provided)";
    if (type == Type::string) {
      // If the call requires a string literal and a positional parameter is
      // given, tell user to use str()
      auto *pos_param = arg.as<PositionalParameter>();
      if (pos_param)
        pos_param->addError() << "Use str($" << pos_param->n << ") to treat $"
                              << pos_param->n << " as a string";
    }
    return false;
  } else if (is_final_pass() && arg.type().GetTy() != type) {
    call.addError() << call.func << "() only supports " << type
                    << " arguments (" << arg.type().GetTy() << " provided)";
    return false;
  }
  return true;
}

bool TypeGraphBuilder::check_symbol(const Call &call,
                                    int arg_num __attribute__((unused)))
{
  auto *arg = call.vargs.at(0).as<String>();
  if (!arg) {
    call.addError() << call.func
                    << "() expects a string literal as the first argument";
    return false;
  }

  std::string re = "^[a-zA-Z0-9./_-]+$";
  bool is_valid = std::regex_match(arg->value, std::regex(re));
  if (!is_valid) {
    call.addError() << call.func
                    << "() expects a string that is a valid symbol (" << re
                    << ") as input (\"" << arg << "\" provided)";
    return false;
  }

  return true;
}

SizedType *TypeGraphBuilder::get_map_type(const Map &map)
{
  const std::string &map_ident = map.ident;
  auto search = map_val_.find(map_ident);
  if (search == map_val_.end())
    return nullptr;
  return &search->second;
}

SizedType *TypeGraphBuilder::get_map_key_type(const Map &map)
{
  if (auto it = map_key_.find(map.ident); it != map_key_.end()) {
    return &it->second;
  }
  return nullptr;
}

// Semantic analysis for assigning a value of the provided type to the given
// map. The type within the passes `Map` node will be updated to reflect the
// new type, if available.
void TypeGraphBuilder::assign_map_type(Map &map,
                                       const SizedType &type,
                                       const Node *loc_node,
                                       AssignMapStatement *assignment)
{
  const std::string &map_ident = map.ident;

  if (type.IsRecordTy() && type.is_tparg) {
    loc_node->addError() << "Storing tracepoint args in maps is not supported";
  }

  auto *maptype = get_map_type(map);
  if (maptype) {
    if (maptype->IsNoneTy()) {
      pass_tracker_.inc_num_unresolved();
      if (is_final_pass())
        map.addError() << "Undefined map: " + map_ident;
      else
        *maptype = type;
    } else if (maptype->GetTy() != type.GetTy()) {
      loc_node->addError() << "Type mismatch for " << map_ident << ": "
                           << "trying to assign value of type '" << type
                           << "' when map already contains a value of type '"
                           << *maptype << "'";
    } else if (maptype->IsSumTy() || maptype->IsMinTy() || maptype->IsMaxTy() ||
               maptype->IsAvgTy() || maptype->IsStatsTy()) {
      if (maptype->IsSigned() != type.IsSigned()) {
        loc_node->addError() << "Type mismatch for " << map_ident << ": "
                             << "trying to assign value of type '" << type
                             << "' when map already contains a value of type '"
                             << *maptype << "'";
      }
    } else if (maptype->IsIntegerTy() && !maptype->IsEqual(type)) {
      auto *integer = assignment ? assignment->expr.as<Integer>() : nullptr;
      if (integer) {
        uint64_t value = integer->value;
        bool can_fit = false;
        if (!maptype->IsSigned()) {
          auto min_max = getUIntTypeRange(*maptype);
          can_fit = value <= min_max.second;
        } else {
          auto min_max = getIntTypeRange(*maptype);
          can_fit = value <= static_cast<uint64_t>(min_max.second);
        }
        if (!can_fit) {
          loc_node->addError() << "Type mismatch for " << map_ident << ": "
                               << "trying to assign value '"
                               << static_cast<uint64_t>(integer->value)
                               << "' which does not fit into the map of type '"
                               << *maptype << "'";
        }
      } else if (maptype->IsSigned() != type.IsSigned()) {
        loc_node->addError() << "Type mismatch for " << map_ident << ": "
                             << "trying to assign value of type '" << type
                             << "' when map already contains a value of type '"
                             << *maptype << "'";
      }
    } else if (maptype->IsStringTy() || maptype->IsTupleTy()) {
      update_string_size(*maptype, type);
    }
    map.value_type = *maptype;
  } else {
    // This map hasn't been seen before.
    map_val_.insert({ map_ident, type });
    if (map_val_[map_ident].IsIntTy()) {
      // Store all integer values as 64-bit in maps, so that there will
      // be space for any integer to be assigned to the map later.
      map_val_[map_ident].SetSize(8);
    }
    map.value_type = map_val_[map_ident];
  }
}

SizedType TypeGraphBuilder::create_key_type(const SizedType &expr_type,
                                            Node &node)
{
  SizedType new_key_type = expr_type;
  if (expr_type.IsTupleTy()) {
    std::vector<SizedType> elements;
    for (const auto &field : expr_type.GetFields()) {
      SizedType keytype = create_key_type(field.type, node);
      elements.push_back(std::move(keytype));
    }
    new_key_type = CreateTuple(Struct::CreateTuple(elements));
  } else if (expr_type.IsIntegerTy()) {
    // Store all integer values as 64-bit in map keys, so that there will
    // be space for any integer in the map key later
    // This should have a better solution.
    new_key_type.SetSign(expr_type.IsSigned());
    new_key_type.SetIntBitWidth(64);
  }

  validate_map_key(new_key_type, node);
  return new_key_type;
}

void TypeGraphBuilder::update_current_key(SizedType &current_key_type,
                                          const SizedType &new_key_type)
{
  if (current_key_type.IsSameType(new_key_type) &&
      (current_key_type.IsStringTy() || current_key_type.IsTupleTy())) {
    update_string_size(current_key_type, new_key_type);
  }
}

void TypeGraphBuilder::validate_new_key(const SizedType &current_key_type,
                                        const SizedType &new_key_type,
                                        const std::string &map_ident,
                                        const Expression &key_expr)
{
  // Map keys can get resized/updated across multiple passes
  // wait till the end to log an error if there is a key mismatch.
  if (!is_final_pass()) {
    return;
  }

  bool valid = true;
  if (current_key_type.IsSameType(new_key_type)) {
    if (current_key_type.IsTupleTy() || current_key_type.IsStringTy()) {
      // This should always be true as map integer keys default to 64 bits
      // and strings get resized (this happens recursively into tuples as
      // well) but keep this here just in case we add larger ints and need to
      // update the map int logic
      if (!new_key_type.FitsInto(current_key_type)) {
        valid = false;
      }
    } else if (!current_key_type.IsEqual(new_key_type)) {
      if (current_key_type.IsIntegerTy()) {
        auto *integer = key_expr.as<Integer>();
        if (integer) {
          uint64_t value = integer->value;
          bool can_fit = false;
          if (current_key_type.IsSigned()) {
            auto min_max = getIntTypeRange(current_key_type);
            can_fit = value <= static_cast<uint64_t>(min_max.second);
          } else {
            auto min_max = getUIntTypeRange(current_key_type);
            can_fit = value <= min_max.second;
          }
          if (!can_fit) {
            key_expr.node().addError()
                << "Argument mismatch for " << map_ident << ": "
                << "trying to access with argument '"
                << static_cast<uint64_t>(integer->value)
                << "' which does not fit into the map of key type '"
                << current_key_type << "'";
          }
        } else if (current_key_type.IsSigned() != new_key_type.IsSigned()) {
          valid = false;
        }
      } else {
        valid = false;
      }
    }
  } else {
    valid = false;
  }

  if (valid) {
    return;
  }

  if (current_key_type.IsNoneTy()) {
    key_expr.node().addError()
        << "Argument mismatch for " << map_ident << ": "
        << "trying to access with arguments: '" << new_key_type
        << "' when map expects no arguments";
  } else {
    key_expr.node().addError()
        << "Argument mismatch for " << map_ident << ": "
        << "trying to access with arguments: '" << new_key_type
        << "' when map expects arguments: '" << current_key_type << "'";
  }
}

bool TypeGraphBuilder::update_string_size(SizedType &type,
                                          const SizedType &new_type)
{
  if (type.IsStringTy() && new_type.IsStringTy() &&
      type.GetSize() != new_type.GetSize()) {
    type.SetSize(std::max(type.GetSize(), new_type.GetSize()));
    return true;
  }

  if (type.IsTupleTy() && new_type.IsTupleTy() &&
      type.GetFieldCount() == new_type.GetFieldCount()) {
    bool updated = false;
    std::vector<SizedType> new_elems;
    for (ssize_t i = 0; i < type.GetFieldCount(); i++) {
      if (update_string_size(type.GetField(i).type, new_type.GetField(i).type))
        updated = true;
      new_elems.push_back(type.GetField(i).type);
    }
    if (updated) {
      type = CreateTuple(Struct::CreateTuple(new_elems));
    }
    return updated;
  }

  return false;
}

SizedType TypeGraphBuilder::create_merged_tuple(const SizedType &left,
                                                const SizedType &right)
{
  assert(left.IsTupleTy() && right.IsTupleTy() &&
         (left.GetFieldCount() == right.GetFieldCount()));

  std::vector<SizedType> new_elems;
  for (ssize_t i = 0; i < left.GetFieldCount(); i++) {
    const auto &leftTy = left.GetField(i).type;
    const auto &rightTy = right.GetField(i).type;

    assert(leftTy.GetTy() == rightTy.GetTy());
    if (leftTy.IsTupleTy()) {
      new_elems.push_back(create_merged_tuple(leftTy, rightTy));
    } else {
      new_elems.push_back(leftTy.GetSize() > rightTy.GetSize() ? leftTy
                                                               : rightTy);
    }
  }
  return CreateTuple(Struct::CreateTuple(new_elems));
}

void TypeGraphBuilder::resolve_struct_type(SizedType &type, Node &node)
{
  const SizedType *inner_type = &type;
  int pointer_level = 0;
  while (inner_type->IsPtrTy()) {
    inner_type = inner_type->GetPointeeTy();
    pointer_level++;
  }
  if (inner_type->IsRecordTy() && !inner_type->GetStruct()) {
    auto struct_type = bpftrace_.structs.Lookup(inner_type->GetName()).lock();
    if (!struct_type) {
      node.addError() << "Cannot resolve unknown type \""
                      << inner_type->GetName() << "\"\n";
    } else {
      type = CreateRecord(inner_type->GetName(), struct_type);
      while (pointer_level > 0) {
        type = CreatePointer(type);
        pointer_level--;
      }
    }
  }
}

variable *TypeGraphBuilder::find_variable(const std::string &var_ident)
{
  if (auto *scope = find_variable_scope(var_ident)) {
    return &variables_[scope][var_ident];
  }
  return nullptr;
}

Node *TypeGraphBuilder::find_variable_scope(const std::string &var_ident)
{
  for (auto *scope : scope_stack_) {
    if (auto search_val = variables_[scope].find(var_ident);
        search_val != variables_[scope].end()) {
      return scope;
    }
  }
  return nullptr;
}

Pass CreateTypeGraphPass()
{
  auto fn = [](ASTContext &ast) -> Result<TypeGraph> {};

  return Pass::create("TypeGraph", fn);
}

} // namespace bpftrace::ast
