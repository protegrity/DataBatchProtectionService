cmake_minimum_required(VERSION 3.14)
project(dbps_server_prj)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

FetchContent_MakeAvailable(crow cppcodec httplib nlohmann_json cxxopts)

add_executable(dbps_api_server 
  src/server/dbps_api_server.cpp
  src/server/encryption_sequencer.cpp
  src/common/json_request.cpp
  src/common/enum_utils.cpp
)

target_include_directories(dbps_api_server PRIVATE
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
  src/common
  src/common/tcb
)

# Add test executable
add_executable(json_request_test
  src/common/json_request_test.cpp
  src/common/json_request.cpp
)

target_include_directories(json_request_test PRIVATE
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  src/common
  src/common/tcb
)

# Add enum utils test executable
add_executable(enum_utils_test
  src/common/enum_utils_test.cpp
  src/common/enum_utils.cpp
)

target_include_directories(enum_utils_test PRIVATE
  src/common
  src/common/tcb
)

# Add encryption sequencer test executable
add_executable(encryption_sequencer_test
  src/server/encryption_sequencer_test.cpp
  src/server/encryption_sequencer.cpp
  src/common/enum_utils.cpp
)

target_include_directories(encryption_sequencer_test PRIVATE
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
  src/common
  src/common/tcb
  src/server
)

# Add decoding utils test executable
add_executable(decoding_utils_test
  src/server/decoding_utils_test.cpp
)

target_include_directories(decoding_utils_test PRIVATE
  src/common
  src/common/tcb
  src/server
)

# Add dbpa interface test executable
add_executable(dbpa_interface_test
  src/common/dbpa_interface_test.cpp
)

target_include_directories(dbpa_interface_test PRIVATE
  src/common
  src/common/tcb
)

# Client test executable
add_executable(dbps_api_client_test
  src/client/dbps_api_client_test.cpp
  src/client/dbps_api_client.cpp
  src/client/httplib_client.cpp
  src/common/json_request.cpp
  src/common/enum_utils.cpp
)

target_include_directories(dbps_api_client_test PRIVATE
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  ${CMAKE_BINARY_DIR}/_deps/httplib-src
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
  ${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include
  src/client
  src/common
  src/common/tcb
)

# Remote DBPA test executable
add_executable(dbpa_remote_test
  src/common/dbpa_remote_test.cpp
  src/common/dbpa_remote.cpp
  src/client/dbps_api_client.cpp
  src/client/httplib_client.cpp
  src/common/json_request.cpp
  src/common/enum_utils.cpp
)

target_include_directories(dbpa_remote_test PRIVATE
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  ${CMAKE_BINARY_DIR}/_deps/httplib-src
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
  ${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include
  src/client
  src/common
  src/common/tcb
)

# DBPA Remote Test Script executable
add_executable(dbpa_remote_testapp
  src/scripts/dbpa_remote_testapp.cpp
  src/common/dbpa_remote.cpp
  src/client/dbps_api_client.cpp
  src/client/httplib_client.cpp
  src/common/json_request.cpp
  src/common/enum_utils.cpp
)

target_include_directories(dbpa_remote_testapp PRIVATE
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  ${CMAKE_BINARY_DIR}/_deps/httplib-src
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
  ${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include
  ${CMAKE_BINARY_DIR}/_deps/cxxopts-src/include
  src/client
  src/common
  src/common/tcb
)

# #########################################################
# Create the shared library (*.so) for the dbps client.
# #########################################################

# Create dynamic library with core components
add_library(dbps_client_lib SHARED
  src/common/dbps_remote_shared_lib_wrapper.cpp
  src/common/dbpa_remote.cpp
  src/client/dbps_api_client.cpp
  src/client/httplib_client.cpp
  src/common/json_request.cpp
  src/common/enum_utils.cpp
)

# Set library properties
set_target_properties(dbps_client_lib PROPERTIES
  VERSION 1.0.0
  SOVERSION 1
  OUTPUT_NAME "dbpsClient"
)

# Include directories for the library
# TODO: are these needed?
target_include_directories(dbps_client_lib PUBLIC
  ${CMAKE_BINARY_DIR}/_deps/cppcodec-src
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
  ${CMAKE_BINARY_DIR}/_deps/httplib-src

  src/common
  src/common/tcb
)

# Export symbols for the library
#target_compile_definitions(dbps_client_lib PRIVATE DBPS_EXPORTS)
