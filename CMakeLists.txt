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

FetchContent_MakeAvailable(crow cppcodec)

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
)

# Add dbpa interface test executable
add_executable(dbpa_interface_test
  src/common/dbpa_interface_test.cpp
)

target_include_directories(dbpa_interface_test PRIVATE
  src/common
  src/common/tcb
)
