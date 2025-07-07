#!/usr/bin/env bash

# Syncs headers from a local kernel repository.
#
# Example usage:
#
#     ./scripts/sync_headers.sh ~/my-linux-repo
#

set -eu
shopt -s globstar

SCRIPT_NAME=$0

usage() {
  echo "Usage:"
  echo "    ${SCRIPT_NAME} <linux-repository>"
  echo ""
  echo " Sync vendored headers for the standard library."
}

if [[ "$#" -ne 1 ]]; then
  usage
  exit 1
fi
declare -r LINUX=$1

# In general, this is the set of headers that is required to make both the
# standard library and useful C extensions. For now, we limit this to the set
# that have been vendored by `libbpf` to build and test (and ensure that they
# are evaluted recursively). As a rule, these should not be system headers but
# rather the Linux uapi headers. For system headers, prefer to vendor minimal
# versions only if absolutely necessary, as full versions can create conflicts
# with the BTF-defined kernel types.
declare -a HEADERS
HEADERS=(
  linux/bpf_common.h
  linux/bpf.h
  linux/btf.h
  linux/errno.h
  linux/fcntl.h
  linux/openat2.h
  linux/if_link.h
  linux/if_xdp.h
  linux/netdev.h
  linux/netlink.h
  linux/pkt_cls.h
  linux/pkt_sched.h
  linux/perf_event.h
  # Force copying as they are only present on some architectures; see below
  # where these are skipped if not present.
  asm/posix_types_64.h
)
declare -a ARCHES
ARCHES=(
  x86
  arm
  arm64
  s390
  powerpc
  mips
  riscv
  loongarch
)

function sync() {
  if [[ -f "src/stdlib/include/$1" ]]; then
    return;
  fi
  echo "Syncing $1..." >&2
  tmpfile=$(mktemp --tmpdir "XXXXXX.c")
  echo "#include <$1>" > "${tmpfile}"
  clang -H -o /dev/null -c "${tmpfile}" 2>&1 | grep -E '.h$' | \
  (while read nesting header; do
    relpath="${header##*/include/}"
    if [[ -f "src/stdlib/include/${relpath}" ]]; then
      continue
    fi
    if [[ "$relpath" =~ asm/.* ]]; then
      echo "  found arch-specific $header"
      asmpath="${relpath##asm/}"
      for arch in "${ARCHES[@]}"; do
        echo "    copying for ${arch}"
        basepath=$(dirname "asm/${arch}/${asmpath}")
        mkdir -p "src/stdlib/include/${basepath}"
        # Attempt to copy from the arch-specific directory, but fall back to
        # the `asm-generic` directory if it is not present there.
        if ! (cp --preserve=mode "${LINUX}/arch/${arch}/include/uapi/asm/${asmpath}" \
                                 "src/stdlib/include/${basepath}" 2>/dev/null ||
              cp --preserve=mode "${LINUX}/include/uapi/asm-generic/${asmpath}" \
                                 "src/stdlib/include/${basepath}" 2>/dev/null); then
          # We can specifically ignore this header, it is only defined for
          # some architectures and is added as a special case.
          if [[ "${asmpath}" != "posix_types_64.h" ]]; then
            echo "    missing $header for $arch?"
            return 1
          fi
        fi
      done
    else
      echo "  found $header" >&2
      basepath=$(dirname "${relpath}")
      mkdir -p "src/stdlib/include/${basepath}"
      cp --preserve=mode "${LINUX}/include/uapi/${relpath}" \
                         "src/stdlib/include/${basepath}"
    fi
  done)
  rm -f "${tmpfile}"
}

# Wipe existing headers.
rm -rf \
  src/stdlib/include/asm \
  src/stdlib/include/asm-* \
  src/stdlib/include/linux

# Recursively vendor headers.
for header in "${HEADERS[@]}"; do
  sync "${header}"
done

# These headers is not part of the user API, but is still used. We only care
# about `compiler-clang` in this case, because we are only compiling via clang.
cp --preserve=mode "${LINUX}/include/linux/compiler_types.h" \
                   "src/stdlib/include/linux"
cp --preserve=mode "${LINUX}/include/linux/compiler_attributes.h" \
                   "src/stdlib/include/linux"
cp --preserve=mode "${LINUX}/include/linux/compiler-clang.h" \
                   "src/stdlib/include/linux"
