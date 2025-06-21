#include "btf/irbuilder.h"

namespace bpftrace::btf {

Result<SizedType> getCompatType(const Void &type)
{
  return CreateVoid();
}

Result<SizedType> getCompatType(const Integer &type)
{
  return CreateInt(8 * type.bytes());
}

Result<SizedType> getCompatType(const Pointer &type)
{
  auto t = type.element_type();
  if (!t) {
    return t.takeError();
  }
  auto ty = getCompatType(*t);
  if (!ty) {
    return ty.takeError();
  }
  return CreatePointer(*ty);
}

Result<SizedType> getCompatType(const Array &type)
{
  auto t = type.element_type();
  if (!t) {
    return t.takeError();
  }
  auto ty = getCompatType(*t);
  if (!ty) {
    return ty.takeError();
  }
  return CreateArray(type.element_count(), *ty);
}

Result<SizedType> getCompatType(const Struct &type)
{
  std::vector<SizedType> fields;
  std::vector<std::string> idents;
  auto f = type.fields();
  if (!f) {
    return f.takeError();
  }
  // We have no ability to control how things are packed,
  // so this may or may not generate the correct type.
  for (const auto &[name, info] : *f) {
    auto ft = getCompatType(info.type);
    if (!ft) {
      return ft.takeError();
    }
    fields.push_back(*ft);
    idents.push_back(name);
  }
  return CreateRecord(Struct::CreateRecord(fields, idents));
}

Result<SizedType> getCompatType(const Enum &type)
{
  auto size = type.size();
  if (!size) {
    return size.takeError();
  }
  return CreateEnum(8 * (*size), type.name()):
}

Result<SizedType> getCompatType(const Enum64 &type)
{
  auto size = type.size();
  if (!size) {
    return size.takeError();
  }
  return CreateEnum(8 * (*size), type.name()):
}

Result<SizedType> getCompatType(const TypeTag &type)
{
  // Values are: user, percpu, rcu.
  if (type.value() == "user") {
    auto t = type.type();
    if (!t) {
      return t.takeError();
    }
    auto ty = getCompatType(*t);
    if (!ty) {
      return ty.takeError();
    }
    ty.SetAS(AddrSpace::User);
    return ty;
  } else {
    return make_error<CompatTypeErrror>(type);
  }
}

Result<SizedType> getCompatType(const Typedef &type)
{
  auto t = type.type();
  if (!t) {
    return t.takeError();
  }
  return getCompatType(*t);
}

} // namespace bpftrace::btf
