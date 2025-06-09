add_compile_options("-Werror=undef")

# Regenerate codegen_includes.cpp whenever anything in the tests/codegen
# directory changes
file(GLOB_RECURSE CODEGEN_SOURCES CONFIGURE_DEPENDS codegen/*.cpp codegen/*.h)
set(CODEGEN_INCLUDES_CPP codegen_includes.cpp)
add_custom_command(
  OUTPUT
    ${CODEGEN_INCLUDES_CPP}
  COMMAND
    ${CMAKE_COMMAND}
    -DCODEGEN_INCLUDES_CPP="${CODEGEN_INCLUDES_CPP}"
    -DCODEGEN_SOURCES="${CODEGEN_SOURCES}"
    -P ${CMAKE_SOURCE_DIR}/tests/codegen/generate_codegen_includes.cmake
  DEPENDS
    ${CODEGEN_SOURCES})

# Codegen tests are based on the IR produced by LLVM 18. The compiler used to
# build bpftrace is also important, as decisions on order of evaluation can
# influence the order of the generated IR.
if(${LLVM_VERSION_MAJOR} VERSION_EQUAL 18 AND ${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
  set(CODEGEN_SRC ${CODEGEN_INCLUDES_CPP})
else()
  set(CODEGEN_SRC "")
  message(STATUS "Disabled codegen tests. Requires GNU/GCC and LLVM 18 (found ${CMAKE_CXX_COMPILER_ID}, LLVM ${LLVM_VERSION_MAJOR})")
endif()

# bpftrace tests require (at minimum) version 1.11.
# There's no great way to enforce a minimum version from cmake -- the cmake
# modules don't respect minimum requested version.
find_package(GTest REQUIRED)
find_package(GMock REQUIRED)
include_directories(SYSTEM ${GTEST_INCLUDE_DIRS} ${GMOCK_INCLUDE_DIRS})

find_package(Threads REQUIRED)

# Add data sources first
add_subdirectory(data)

# Common test dependencies and settings
function(add_bpftrace_test test_name test_source)
  add_executable(${test_name} ${test_source} ${ARGN})
  target_include_directories(${test_name} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  target_include_directories(${test_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_definitions(${test_name} PRIVATE TEST_CODEGEN_LOCATION="${CMAKE_SOURCE_DIR}/tests/codegen/llvm/")
  target_link_libraries(${test_name} libbpftrace)
  target_link_libraries(${test_name} ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARIES})
  target_link_libraries(${test_name} ${CMAKE_THREAD_LIBS_INIT})
  target_compile_definitions(${test_name} PRIVATE ${BPFTRACE_FLAGS})

  if(BUILD_ASAN)
    target_compile_options(${test_name} PUBLIC "-fsanitize=address")
    target_link_options(${test_name} PUBLIC "-fsanitize=address")
  endif()

  gtest_discover_tests(${test_name})
  add_dependencies(${test_name} data_source_dwarf data_source_btf data_source_funcs parser)
endfunction()

# Add individual test targets
add_bpftrace_test(test_ast ast.cpp)
add_bpftrace_test(test_async_action async_action.cpp)
add_bpftrace_test(test_bpfbytecode bpfbytecode.cpp)
add_bpftrace_test(test_bpftrace bpftrace.cpp)
add_bpftrace_test(test_child child.cpp)
add_bpftrace_test(test_clang_parser clang_parser.cpp)
add_bpftrace_test(test_config config.cpp)
add_bpftrace_test(test_collect_nodes collect_nodes.cpp)
add_bpftrace_test(test_deprecated deprecated.cpp)
add_bpftrace_test(test_field_analyser field_analyser.cpp)
add_bpftrace_test(test_fold_literals fold_literals.cpp)
add_bpftrace_test(test_function_registry function_registry.cpp)
add_bpftrace_test(test_imports imports.cpp)
add_bpftrace_test(test_location location.cpp)
add_bpftrace_test(test_log log.cpp)
add_bpftrace_test(test_macro_expansion macro_expansion.cpp)
add_bpftrace_test(test_mocks mocks.cpp)
add_bpftrace_test(test_output output.cpp)
add_bpftrace_test(test_parser parser.cpp)
add_bpftrace_test(test_portability_analyser portability_analyser.cpp)
add_bpftrace_test(test_procmon procmon.cpp)
add_bpftrace_test(test_probe probe.cpp)
add_bpftrace_test(test_config_analyser config_analyser.cpp)
add_bpftrace_test(test_pass_manager pass_manager.cpp)
add_bpftrace_test(test_pid_filter_pass pid_filter_pass.cpp)
add_bpftrace_test(test_recursion_check recursion_check.cpp)
add_bpftrace_test(test_resource_analyser resource_analyser.cpp)
add_bpftrace_test(test_result result.cpp)
add_bpftrace_test(test_required_resources required_resources.cpp)
add_bpftrace_test(test_return_path_analyser return_path_analyser.cpp)
add_bpftrace_test(test_scopeguard scopeguard.cpp)
add_bpftrace_test(test_semantic_analyser semantic_analyser.cpp)
add_bpftrace_test(test_temp temp.cpp)
add_bpftrace_test(test_tracepoint_format_parser tracepoint_format_parser.cpp)
add_bpftrace_test(test_types types.cpp)
add_bpftrace_test(test_unstable_feature unstable_feature.cpp)
add_bpftrace_test(test_utils utils.cpp)

# Add codegen tests if available
if(NOT "${CODEGEN_SRC}" STREQUAL "")
  add_bpftrace_test(test_codegen ${CODEGEN_SRC} main.cpp)
endif()

add_subdirectory(testprogs)
add_subdirectory(testlibs)


#
# Runtime Tests
#
configure_file(runtime-tests.sh runtime-tests.sh @ONLY)
add_custom_target(
  runtime_tests
  COMMAND ./runtime-tests.sh
  DEPENDS
    testprogs
    testlibs
    ${CMAKE_BINARY_DIR}/src/bpftrace
)
add_test(NAME runtime_tests COMMAND ./runtime-tests.sh)

file(GLOB_RECURSE runtime_test_src_files
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  CONFIGURE_DEPENDS
  runtime/*
)
list(REMOVE_ITEM runtime_test_src_files runtime/engine/cmake_vars.py)

set(runtime_test_files)
foreach(runtime_test_file ${runtime_test_src_files})
  add_custom_command(
    OUTPUT
      ${CMAKE_CURRENT_BINARY_DIR}/${runtime_test_file}
    COMMAND ${CMAKE_COMMAND} -E copy
      ${CMAKE_CURRENT_SOURCE_DIR}/${runtime_test_file}
      ${CMAKE_CURRENT_BINARY_DIR}/${runtime_test_file}
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/${runtime_test_file}
  )
  list(APPEND
    runtime_test_files
    ${CMAKE_CURRENT_BINARY_DIR}/${runtime_test_file}
  )
endforeach()
add_custom_target(runtime_test_files ALL DEPENDS ${runtime_test_files})
add_dependencies(runtime_tests runtime_test_files)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/runtime/engine)
configure_file(runtime/engine/cmake_vars.py ${CMAKE_CURRENT_BINARY_DIR}/runtime/engine/ @ONLY)



configure_file(tools-parsing-test.sh tools-parsing-test.sh COPYONLY)
add_custom_target(tools-parsing-test COMMAND ./tools-parsing-test.sh)
add_test(NAME tools-parsing-test COMMAND ./tools-parsing-test.sh)

if(ENABLE_TEST_VALIDATE_CODEGEN)
  if(${LLVM_VERSION_MAJOR} VERSION_EQUAL 18)
    message(STATUS "Adding codegen-validator test")
    configure_file(codegen-validator.sh codegen-validator.sh COPYONLY)
    add_custom_target(codegen-validator COMMAND ./codegen-validator.sh)
    add_test(NAME codegen-validator COMMAND ./codegen-validator.sh ${CMAKE_SOURCE_DIR})
  else()
    message(STATUS "Not building with LLVM 18, skipping codegen-validator test")
  endif()
else()
  message(STATUS "codegen-validator test disabled")
endif()
