function(embed_files)
  message(STATUS ${ARGV})
  cmake_parse_arguments(
    PARSE_ARGV
    0
    arg
    ""
    "NAMESPACE;OUTPUT_HEADER;OUTPUT_SOURCE"
    "SRCS"
  )

  set(output_header ${CMAKE_CURRENT_BINARY_DIR}/${arg_OUTPUT_HEADER})
  set(output_source ${CMAKE_CURRENT_BINARY_DIR}/${arg_OUTPUT_SOURCE})

  set(prologue "#include <string_view>\n\nnamespace ${arg_NAMESPACE} {\n")
  get_filename_component(header_name ${output_header} NAME)
  file(WRITE ${output_header} ${prologue})
  file(WRITE ${output_source} "#include \"${header_name}\"\n\n")
  file(APPEND ${output_source} ${prologue})

  foreach(file ${arg_SRCS})
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${file})
    get_filename_component(filename ${file} NAME)
    string(MAKE_C_IDENTIFIER ${filename} varname)
    file(READ ${file} contents)
    file(APPEND ${output_header} "extern const std::string_view ${varname};\n")
    file(APPEND ${output_source} "const std::string_view ${varname} = R\"CONTENTS(${contents})CONTENTS\";\n\n")
  endforeach()

  set(epilogue "} // namespace ${arg_NAMESPACE}")
  file(APPEND ${output_header} ${epilogue})
  file(APPEND ${output_source} ${epilogue})
endfunction()

function(embeded_files_library name glob_pattern)
  file(GLOB srcs ${glob_pattern})
  cmake_parse_arguments(PARSE_ARGV 2 arg "" "" "")
  embed_files(OUTPUT_HEADER ${name}.h OUTPUT_SOURCE ${name}.cpp SRCS ${srcs} ${arg_UNPARSED_ARGUMENTS})
  add_library(${name} STATIC ${CMAKE_CURRENT_BINARY_DIR}/${name}.cpp)
endfunction()
