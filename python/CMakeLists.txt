find_package(Python3 COMPONENTS Interpreter Development QUIET)
if(NOT Python3_FOUND)
  message(WARNING "Python3 not found. Python bindings will not be built.")
  set(BUILD_PYTHON_BINDINGS OFF)
  return()
endif()

find_package(pybind11 QUIET)
if(NOT pybind11_FOUND)
  message(WARNING "pybind11 not found and could not be installed. Python bindings will not be built.")
  set(BUILD_PYTHON_BINDINGS OFF)
  return()
endif()

pybind11_add_module(_bpftrace_native
  src/bpftrace_native.cpp
  src/map_wrapper.cpp
)
target_link_libraries(_bpftrace_native PRIVATE libbpftrace)
target_compile_definitions(_bpftrace_native PRIVATE VERSION_INFO=${BPFTRACE_VERSION})

install(TARGETS _bpftrace_native
  LIBRARY DESTINATION ${Python3_SITEARCH}
)
install(FILES bpftrace.py
  DESTINATION ${Python3_SITEARCH}
)
install(DIRECTORY examples/
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/bpftrace/python-examples
  FILES_MATCHING PATTERN "*.py"
)

if(BUILD_TESTING)
  add_test(
    NAME python_transpiler_tests
    COMMAND ${Python3_EXECUTABLE} -m unittest test_bpftrace.py -v
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )
  set_tests_properties(python_transpiler_tests PROPERTIES
    ENVIRONMENT "PYTHONPATH=${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_SOURCE_DIR}"
  )
endif()
