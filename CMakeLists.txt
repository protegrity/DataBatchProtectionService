cmake_minimum_required(VERSION 3.14)
project(dbps_server_prj)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  crow
  GIT_REPOSITORY https://github.com/CrowCpp/crow.git
  GIT_TAG v1.0+2
)

FetchContent_MakeAvailable(crow)

add_executable(dbps_api_server src/server/dbps_api_server.cpp)

target_include_directories(dbps_api_server PRIVATE
  ${CMAKE_BINARY_DIR}/_deps/crow-src/include
)
