cmake_minimum_required(VERSION 3.14)
project(dbps_server_prj)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build options
option(BUILD_TESTS "Build test executables" ON)
option(BUILD_CLIENT_LIB "Build client shared library" ON)

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
  GIT_TAG v0.2
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

FetchContent_MakeAvailable(crow cppcodec httplib nlohmann_json cxxopts googletest)

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
  src/common/tcb
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
)

# Server components library
add_library(dbps_server_lib STATIC 
  src/server/encryption_sequencer.cpp
)
target_link_libraries(dbps_server_lib PUBLIC dbps_common_lib)
target_include_directories(dbps_server_lib PUBLIC
  src/server
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
)

# Client components library (depends on httplib, nlohmann/json, and cppcodec)
add_library(dbps_client_lib STATIC 
  src/client/dbps_api_client.cpp
  src/client/httplib_client.cpp
)
target_link_libraries(dbps_client_lib PUBLIC dbps_common_lib)
target_include_directories(dbps_client_lib PUBLIC
  src/client
  ${CMAKE_BINARY_DIR}/_deps/httplib-src
  ${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
)

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
  target_link_libraries(json_request_test dbps_common_lib)
  target_include_directories(json_request_test PRIVATE
    ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  )

  # Enum utils tests
  add_executable(enum_utils_test src/common/enum_utils_test.cpp)
  target_link_libraries(enum_utils_test dbps_common_lib)

  # Encryption sequencer tests
  add_executable(encryption_sequencer_test src/server/encryption_sequencer_test.cpp)
  target_link_libraries(encryption_sequencer_test 
    dbps_server_lib
    dbps_common_lib
  )

  # Decoding utils tests
  add_executable(decoding_utils_test src/server/decoding_utils_test.cpp)
  target_link_libraries(decoding_utils_test dbps_common_lib)
  target_include_directories(decoding_utils_test PRIVATE src/server)

  # DBPA interface tests
  add_executable(dbpa_interface_test src/common/dbpa_interface_test.cpp)
  target_link_libraries(dbpa_interface_test dbps_common_lib)

  # Client API tests
  add_executable(dbps_api_client_test src/client/dbps_api_client_test.cpp)
  target_link_libraries(dbps_api_client_test 
    dbps_client_lib
    dbps_common_lib
  )
  target_include_directories(dbps_api_client_test PRIVATE
    ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  )

  # Remote DBPA tests
  add_executable(dbpa_remote_test src/common/dbpa_remote_test.cpp)
  target_link_libraries(dbpa_remote_test 
    dbps_remote_lib
    dbps_client_lib
    dbps_common_lib
    gtest_main
  )
endif()

# =============================================================================
# Shared Library (Client Library)
# =============================================================================

if(BUILD_CLIENT_LIB)
  # Create dynamic library with core components
  add_library(dbps_client_shared SHARED
    src/common/dbps_remote_shared_lib_wrapper.cpp
    src/common/dbpa_remote.cpp
    src/client/dbps_api_client.cpp
    src/client/httplib_client.cpp
    src/common/json_request.cpp
  )

  # Set library properties
  set_target_properties(dbps_client_shared PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME "dbpsClient"
  )


  # Link dependencies
  target_link_libraries(dbps_client_shared 
    dbps_remote_lib
    dbps_client_lib
    dbps_common_lib
  )

  # Include directories for the library
  target_include_directories(dbps_client_shared PUBLIC
    ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
    ${CMAKE_BINARY_DIR}/_deps/crow-src/include
    ${CMAKE_BINARY_DIR}/_deps/httplib-src
    src/common
    src/common/tcb
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
  COMMENT "Building all libraries"
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
      dbpa_interface_test
      dbps_api_client_test
      dbpa_remote_test
    COMMENT "Building all tests"
  )
endif()

# Client shared library target
if(BUILD_CLIENT_LIB)
  add_custom_target(client_shared
    DEPENDS dbps_client_shared
    COMMENT "Building client shared library"
  )
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
if(BUILD_CLIENT_LIB)
  add_dependencies(all_targets client_shared)
endif()
