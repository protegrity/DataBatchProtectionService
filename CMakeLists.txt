cmake_minimum_required(VERSION 3.5)
project(dbps_server_prj)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build all targets (including STATIC libs) with position independent code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build options
option(BUILD_TESTS "Build test executables" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

# Enable CTest and GoogleTest integration
enable_testing()
include(CTest)

# =============================================================================
# Dependencies
# =============================================================================
include(FetchContent)

# Crow is a lightweight framework for running web APIs
FetchContent_Declare(
  crow
  GIT_REPOSITORY https://github.com/CrowCpp/crow.git
  GIT_TAG v1.0+2
)

# cppcodec is a header-only base64 library
FetchContent_Declare(
  cppcodec
  GIT_REPOSITORY https://github.com/tplgy/cppcodec.git
  GIT_TAG 8019b8b580f8573c33c50372baec7039dfe5a8ce # points to the head of main as of 11/11/2025
)

# httplib is a header-only HTTP client library
FetchContent_Declare(
  httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.14.3
)

# nlohmann/json is a header-only JSON library
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)

# tcb/span - header-only span implementation (match Arrow's approach)
FetchContent_Declare(
  tcb_span_upstream
  GIT_REPOSITORY https://github.com/tcbrindle/span.git
  GIT_TAG master
)
FetchContent_GetProperties(tcb_span_upstream)
if(NOT tcb_span_upstream_POPULATED)
  FetchContent_Populate(tcb_span_upstream)
endif()
add_library(tcb_span INTERFACE)
target_include_directories(tcb_span INTERFACE ${tcb_span_upstream_SOURCE_DIR}/include)

# cxxopts is a header-only command line parser
FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG v3.1.0
)

# Google Test for unit testing
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)

# jwt-cpp is a header-only JWT library
FetchContent_Declare(
  jwt-cpp
  GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
  GIT_TAG master
)

# Snappy is a fast compression/decompression library
FetchContent_Declare(
  snappy
  GIT_REPOSITORY https://github.com/google/snappy.git
  GIT_TAG 1.1.10
)

# Fetch dependencies

# Disable dependency tests for cppcodec
# Dependency tests are picked up by GTest/CTest. 
# This disabling is needed as not all of the cppcodec tests pass, and we want to avoid 
# generating noise in the tests where the noise is caused by the third-party tests.
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(cppcodec)
set(BUILD_TESTING ON CACHE BOOL "" FORCE)

# Disable Snappy tests to avoid conflicts with our GoogleTest
# Snappy includes its own GoogleTest which conflicts with our FetchContent GoogleTest
set(SNAPPY_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(snappy)
set(SNAPPY_BUILD_TESTS ON CACHE BOOL "" FORCE)

# Suppress warnings from Snappy's source code
if(TARGET snappy)
    target_compile_options(snappy PRIVATE
        -Wno-sign-compare
    )
endif()

FetchContent_MakeAvailable(crow httplib nlohmann_json cxxopts googletest jwt-cpp)

# Make GoogleTest helper macros available (gtest_discover_tests)
include(GoogleTest)

# =============================================================================
# Library Definitions
# =============================================================================

# Common utilities library (depends on crow for JSON parsing)
add_library(dbps_common_lib STATIC 
  src/common/json_request.cpp
  src/common/enum_utils.cpp
)
target_include_directories(dbps_common_lib PUBLIC
  src/common
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
)
target_link_libraries(dbps_common_lib PUBLIC tcb_span)

# Server components library
add_library(dbps_server_lib STATIC 
  src/server/encryption_sequencer.cpp
  src/server/auth_utils.cpp
  src/server/decoding_utils.cpp
  src/server/compression_utils.cpp
)
target_link_libraries(dbps_server_lib PUBLIC dbps_common_lib snappy)
target_include_directories(dbps_server_lib PUBLIC
  src/server
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
  ${CMAKE_BINARY_DIR}/_deps/jwt-cpp-src/include
  ${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include
  ${CMAKE_BINARY_DIR}/_deps/snappy-src
)

# Find and link OpenSSL (required by jwt-cpp)
find_package(OpenSSL REQUIRED)
target_link_libraries(dbps_server_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# Client components library (depends on httplib, nlohmann/json, and cppcodec)
add_library(dbps_client_lib STATIC 
  src/client/dbps_api_client.cpp
  src/client/httplib_client.cpp
  src/client/httplib_pool_registry.cpp
  src/client/httplib_pooled_client.cpp
)
target_link_libraries(dbps_client_lib PUBLIC dbps_common_lib)
target_include_directories(dbps_client_lib PUBLIC
  src/client
  ${CMAKE_BINARY_DIR}/_deps/httplib-src
  ${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
)
target_link_libraries(dbps_client_lib PUBLIC tcb_span)

# Remote DBPA library
add_library(dbps_remote_lib STATIC 
  src/common/dbpa_remote.cpp
)
target_link_libraries(dbps_remote_lib PUBLIC 
  dbps_client_lib
  dbps_common_lib
)
target_include_directories(dbps_remote_lib PUBLIC
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
)

# Local DBPA library
add_library(dbps_local_lib STATIC 
  src/common/dbpa_local.cpp
)
target_link_libraries(dbps_local_lib PUBLIC 
  dbps_server_lib
  dbps_common_lib
)
target_include_directories(dbps_local_lib PUBLIC
  src/server
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
  ${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include
)

# Ensure PIC on static libs that are linked into shared libraries
set_target_properties(dbps_common_lib dbps_server_lib dbps_local_lib
  PROPERTIES POSITION_INDEPENDENT_CODE ON)

# =============================================================================
# Main Executables
# =============================================================================

# Main API server
add_executable(dbps_api_server src/server/dbps_api_server.cpp)
target_link_libraries(dbps_api_server 
  dbps_server_lib
  dbps_common_lib
)
target_include_directories(dbps_api_server PRIVATE
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  ${CMAKE_BINARY_DIR}/_deps/cxxopts-src/include
)

# DBPA Remote Test Script executable
add_executable(dbpa_remote_testapp src/scripts/dbpa_remote_testapp.cpp)
target_link_libraries(dbpa_remote_testapp 
  dbps_remote_lib
  dbps_client_lib
  dbps_common_lib
)
target_include_directories(dbpa_remote_testapp PRIVATE
  ${CMAKE_BINARY_DIR}/_deps/cxxopts-src/include
)

# =============================================================================
# Test Executables
# =============================================================================

if(BUILD_TESTS)
  # JSON request tests
  add_executable(json_request_test src/common/json_request_test.cpp)
  target_link_libraries(json_request_test
    dbps_common_lib
    gtest_main
  )
  target_include_directories(json_request_test PRIVATE
    ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  )

  # Enum utils tests
  add_executable(enum_utils_test src/common/enum_utils_test.cpp)
  target_link_libraries(enum_utils_test
    dbps_common_lib
    gtest_main
  )

  # Encryption sequencer tests
  add_executable(encryption_sequencer_test src/server/encryption_sequencer_test.cpp)
  target_link_libraries(encryption_sequencer_test 
    dbps_server_lib
    dbps_common_lib
    gtest_main
  )

  # Decoding utils tests
  add_executable(decoding_utils_test src/server/decoding_utils_test.cpp)
  target_link_libraries(decoding_utils_test
    dbps_server_lib
    dbps_common_lib
    gtest_main
  )
  target_include_directories(decoding_utils_test PRIVATE src/server)

  # Compression utils tests
  add_executable(compression_utils_test src/server/compression_utils_test.cpp)
  target_link_libraries(compression_utils_test
    dbps_server_lib
    dbps_common_lib
    gtest_main
  )
  target_include_directories(compression_utils_test PRIVATE src/server)

  # Auth utils tests
  add_executable(auth_utils_test src/server/auth_utils_test.cpp)
  target_link_libraries(auth_utils_test
    dbps_server_lib
    dbps_common_lib
    gtest_main
  )
  target_include_directories(auth_utils_test PRIVATE src/server)

  # DBPA interface tests
  add_executable(dbpa_interface_test src/common/dbpa_interface_test.cpp)
  target_link_libraries(dbpa_interface_test
    dbps_common_lib
    gtest_main
  )

  # DBPA utils tests
  add_executable(dbpa_utils_test src/common/dbpa_utils_test.cpp)
  target_link_libraries(dbpa_utils_test 
    dbps_common_lib
    gtest_main
  )

  # Client API tests
  add_executable(dbps_api_client_test src/client/dbps_api_client_test.cpp)
  target_link_libraries(dbps_api_client_test 
    dbps_client_lib
    dbps_common_lib
    gtest_main
  )
  target_include_directories(dbps_api_client_test PRIVATE
    ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  )

  # Pool registry tests
  add_executable(httplib_pool_registry_test src/client/httplib_pool_registry_test.cpp)
  target_link_libraries(httplib_pool_registry_test 
    dbps_client_lib
    dbps_common_lib
    gtest_main
  )

  # Pooled client tests
  add_executable(httplib_pooled_client_test src/client/httplib_pooled_client_test.cpp)
  target_link_libraries(httplib_pooled_client_test 
    dbps_client_lib
    dbps_common_lib
    gtest_main
  )

  # Remote DBPA tests
  add_executable(dbpa_remote_test src/common/dbpa_remote_test.cpp)
  target_link_libraries(dbpa_remote_test 
    dbps_remote_lib
    dbps_client_lib
    dbps_common_lib
    gtest_main
  )

  # Local DBPA tests
  add_executable(dbpa_local_test src/common/dbpa_local_test.cpp)
  target_link_libraries(dbpa_local_test 
    dbps_local_lib
    dbps_server_lib
    dbps_common_lib
    gtest_main
  )
endif()

# =============================================================================
# Shared Library (Client Library)
# =============================================================================

if(BUILD_SHARED_LIBS)
  # Create dynamic library with core components
  add_library(remote_agent_shared SHARED
    src/common/dbps_remote_shared_lib_wrapper.cpp
    src/common/dbpa_remote.cpp
    src/client/dbps_api_client.cpp
    src/client/httplib_client.cpp
    src/common/json_request.cpp
  )

  # Set library properties
  set_target_properties(remote_agent_shared PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME "dbpsRemoteAgent"
  )

  # Link dependencies
  target_link_libraries(remote_agent_shared 
    dbps_remote_lib
    dbps_client_lib
    dbps_common_lib
  )

  # Include directories for the library
  target_include_directories(remote_agent_shared PUBLIC
    ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
    ${CMAKE_BINARY_DIR}/_deps/crow-src/include
    ${CMAKE_BINARY_DIR}/_deps/httplib-src
    src/common
  )

  # Create dynamic library for local agent
  add_library(local_agent_shared SHARED
    src/common/dbps_local_shared_lib_wrapper.cpp
  )

  # Set library properties for local client
  set_target_properties(local_agent_shared PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME "dbpsLocalAgent"
  )

  # Link dependencies
  target_link_libraries(local_agent_shared
    PRIVATE dbps_local_lib
  )

  # Include directories for the local library
  target_include_directories(local_agent_shared PUBLIC
    ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
    ${CMAKE_BINARY_DIR}/_deps/crow-src/include
    src/common
    src/server
  )
endif()

# =============================================================================
# Custom Targets
# =============================================================================

# Libraries target
add_custom_target(libraries
  DEPENDS 
    dbps_common_lib
    dbps_server_lib
    dbps_client_lib
    dbps_remote_lib
    dbps_local_lib
  COMMENT "Building all libraries"
)

add_custom_target(shared_libraries
  DEPENDS 
    remote_agent_shared
    local_agent_shared
  COMMENT "Building all shared libraries"
)

# Main executables target
add_custom_target(executables
  DEPENDS 
    dbps_api_server
    dbpa_remote_testapp
  COMMENT "Building main executables"
)

# Tests target
if(BUILD_TESTS)
  add_custom_target(tests
    DEPENDS 
      json_request_test
      enum_utils_test
      encryption_sequencer_test
      decoding_utils_test
      compression_utils_test
      auth_utils_test
      dbpa_interface_test
      dbpa_utils_test
      dbps_api_client_test
      dbpa_remote_test
      dbpa_local_test
      httplib_pool_registry_test
      httplib_pooled_client_test
    COMMENT "Building all tests"
  )

  # Register tests with CTest via GoogleTest discovery
  gtest_discover_tests(json_request_test)
  gtest_discover_tests(enum_utils_test)
  gtest_discover_tests(encryption_sequencer_test)
  gtest_discover_tests(decoding_utils_test)
  gtest_discover_tests(compression_utils_test)
  gtest_discover_tests(auth_utils_test)
  gtest_discover_tests(dbpa_interface_test)
  gtest_discover_tests(dbpa_utils_test)
  gtest_discover_tests(dbps_api_client_test)
  gtest_discover_tests(dbpa_remote_test)
  gtest_discover_tests(dbpa_local_test)
  gtest_discover_tests(httplib_pool_registry_test)
  gtest_discover_tests(httplib_pooled_client_test)
endif()

# All target (everything)
add_custom_target(all_targets
  DEPENDS 
    libraries
    executables
  COMMENT "Building all targets"
)

# Add tests to all_targets if enabled
if(BUILD_TESTS)
  add_dependencies(all_targets tests)
endif()

# Add client shared library to all_targets if enabled
if(BUILD_SHARED_LIBS)
  add_dependencies(all_targets shared_libraries)
endif()
