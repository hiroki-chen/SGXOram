# # Set the minimum version of CMake required.
# cmake_minimum_required(VERSION 3.20.0 FATAL_ERROR)

# # Set the project name and version.
# project(PartitionORAM VERSION 1.0 LANGUAGES CXX)

# # C++ standard settings.
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)
# set(CMAKE_CXX_EXTENSIONS OFF)
# set(CMAKE_BUILD_TYPE RELEASE)

# # Check the compiler
# set (SUPPRESS_WARN_FLAGS "${SUPPRESS_WARN_FLAGS} -Wno-return-type")
# if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
#     set(SUPPRESS_WARN_FLAGS "${SUPPRESS_WARN_FLAGS} -Wno-sign-compare \
#                                                      -Wno-unused-parameter \
#                                                      -Wno-nullability-completeness \
#                                                      -Wno-register")
# elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
#     set(SUPPRESS_WARN_FLAGS "${SUPPRESS_WARN_FLAGS} -Wno-sign-compare -Wno-unused-parameter")

# endif ()
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_DEBUG} ${SUPPRESS_WARN_FLAGS}")

# if ("${PROJECT_SOURCE_DIR}" STREQUAL "${PROJECT_BINARY_DIR}")
#     message("In-source builds are not allowed.")
# endif ()

# # Configure the server target.
# file(GLOB_RECURSE SERVER_SRC RELATIVE ${PROJECT_SOURCE_DIR} 
#     "src/server/*.cc"
# )

# add_executable(server ${SERVER_SRC})
# target_include_directories(server PUBLIC ${PROJECT_SOURCE_DIR}/include/server)

cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
project(PartitionORAM LANGUAGES CXX)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(protos)
add_subdirectory(base)