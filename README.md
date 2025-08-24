# Data Batch Protection Service

## Table of Contents
- [API server](#api-server)
- [Development Dockerfile](#development-dockerfile)
- [Building the server docker image](#building-the-server-docker-image)
- [Running the server locally from the docker image](#running-the-server-locally-from-the-docker-image)
- [For development](#for-development)
- [Running Unittests](#running-unittests)
  - [Build-n-run tests (Compact version)](#build-n-run-tests-compact-version)
  - [Build the tests](#build-the-tests)
  - [Run the tests](#run-the-tests)
- [Running DBPA remote testing app](#running-dbpa-remote-testing-app)


## API server

[View API Swagger file](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/protegrity/DataBatchProtectionService/dev_phase2/src/common/swagger.yaml)

## Development Dockerfile
- `Dockerfile` is configured for development. Although Docker is mostly used for production deployments, it can also provide a stable environment during development.
- Docker images can be created but these are primarily for testing. In these cases, code on the local development environment is copied to the Docker container and built.
- For faster development the local directories can be mounted on the docker container to be built.

## Building the server docker image

```
$ docker build -t dbps_server .
```

or with no cache
```
$ docker build --no-cache -t dbps_server .
```


This compiles the dbps_api_server binary and builds the image using the Dockerfile.

## Running the server locally from the docker image

```
$ docker run -it --rm -p 18080:18080 dbps_server
```

then open a browser to check: http://localhost:18080/statusz

## For development

Build the image once:
```
$ docker build --no-cache -t dbps_server .
```

Run docker container with source files mounted:
```
$ docker run -it --rm  -v $(pwd):/app  -p 18080:18080  dbps_server /bin/bash
```

Make changes to source files as needed.

Then build and run manually from inside the docker container bash
```
# Build then run server
cmake -B build -S . -G Ninja && cmake --build build --target dbps_api_server
./build/dbps_api_server
```

## Running Unittests

The project includes unit tests for the JSON request parsing classes. To run the tests:

### Build-n-run tests (Compact version)
```
cmake -B build -S . -G Ninja && cmake --build build --target json_request_test  && ./build/json_request_test
cmake -B build -S . -G Ninja && cmake --build build --target enum_utils_test && ./build/enum_utils_test
cmake -B build -S . -G Ninja && cmake --build build --target encryption_sequencer_test && ./build/encryption_sequencer_test
cmake -B build -S . -G Ninja && cmake --build build --target dbpa_interface_test && ./build/dbpa_interface_test
cmake -B build -S . -G Ninja && cmake --build build --target dbps_api_client_test && ./build/dbps_api_client_test
cmake -B build -S . -G Ninja && cmake --build build --target dbpa_remote_test && ./build/dbpa_remote_test
```

### Build the tests
```
echo "----- build: json_request_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target json_request_test \
  || { echo "❌ FAILED: json_request_test"; false; } && echo

echo "----- build: enum_utils_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target enum_utils_test \
  || { echo "❌ FAILED: enum_utils_test"; false; } && echo

echo "----- build: encryption_sequencer_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target encryption_sequencer_test \
  || { echo "❌ FAILED: encryption_sequencer_test"; false; } && echo

echo "----- build: dbpa_interface_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target dbpa_interface_test \
  || { echo "❌ FAILED: dbpa_interface_test"; false; } && echo

echo "----- build: dbps_api_client_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target dbps_api_client_test \
  || { echo "❌ FAILED: dbps_api_client_test"; false; } && echo

echo "----- build: dbpa_remote_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target dbpa_remote_test \
  || { echo "❌ FAILED: dbpa_remote_test"; false; } && echo
```

### Run the tests
```
echo "----- run: json_request_test -----" && \
./build/json_request_test \
  || { echo "❌ FAILED: json_request_test"; false; } && echo

echo "----- run: enum_utils_test -----" && \
./build/enum_utils_test \
  || { echo "❌ FAILED: enum_utils_test"; false; } && echo

echo "----- run: encryption_sequencer_test -----" && \
./build/encryption_sequencer_test \
  || { echo "❌ FAILED: encryption_sequencer_test"; false; } && echo

echo "----- run: dbpa_interface_test -----" && \
./build/dbpa_interface_test \
  || { echo "❌ FAILED: dbpa_interface_test"; false; } && echo

echo "----- run: dbps_api_client_test -----" && \
./build/dbps_api_client_test \
  || { echo "❌ FAILED: dbps_api_client_test"; false; } && echo

echo "----- run: dbpa_remote_test -----" && \
./build/dbpa_remote_test \
  || { echo "❌ FAILED: dbpa_remote_test"; false; } && echo
```

## Running DBPA remote testing app
```
# Build the application
cmake -B build -S . -G Ninja
cmake --build build --target dbpa_remote_testapp

# Run the application
./build/dbpa_remote_testapp
./build/dbpa_remote_testapp --server_url=http://localhost:18080
./build/dbpa_remote_testapp --help
```
