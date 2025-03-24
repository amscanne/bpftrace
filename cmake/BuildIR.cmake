# Functions to build intermediate BPF modules.

function(btf_header NAME)
  cmake_parse_arguments(
    ARG
    ""
    "OUTPUT;SOURCE"
    ""
    ${ARGN}
  )
  if (NOT DEFINED ARG_SOURCE)
    set(ARG_SOURCE "/sys/kernel/btf/vmlinux")
  endif ()
  if (NOT DEFINED ARG_OUTPUT)
    set(ARG_OUTPUT "${NAME}.h")
  endif ()
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OUTPUT}
    COMMAND bpftool btf dump file "${ARG_SOURCE}" format c > ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OUTPUT}
    VERBATIM
  )
  add_custom_target(${NAME}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OUTPUT}
  )
endfunction()

function(llvm_ir NAME)
  cmake_parse_arguments(
    ARG
    ""
    "OUTPUT;SOURCE"
    "DEPENDS"
    ${ARGN}
  )
  if (NOT DEFINED ARG_SOURCE)
    set(ARG_SOURCE "${NAME}.c")
  endif ()
  if (NOT DEFINED ARG_OUTPUT)
    set(ARG_OUTPUT "${NAME}.ll")
  endif ()
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OUTPUT}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${ARG_SOURCE}
    COMMAND clang -S -emit-llvm -g -target bpf -O0 -I ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${ARG_SOURCE} > ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OUTPUT}
    VERBATIM
  )
  add_custom_target(${NAME}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OUTPUT}
            ${ARG_DEPENDS}
  )
endfunction()
