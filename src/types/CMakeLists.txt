add_library(types STATIC
  async.cpp
  probes.cpp
  sized.cpp
  struct.cpp
)
target_link_libraries(types PRIVATE util)
