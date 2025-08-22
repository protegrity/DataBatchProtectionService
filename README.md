# Data Batch Protection Service

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

## Running Tests

The project includes unit tests for the JSON request parsing classes. To run the tests:

### Build-n-run tests (Compact version)
```
cmake -B build -S . -G Ninja && cmake --build build --target json_request_test  && ./build/json_request_test
cmake -B build -S . -G Ninja && cmake --build build --target enum_utils_test && ./build/enum_utils_test
cmake -B build -S . -G Ninja && cmake --build build --target encryption_sequencer_test && ./build/encryption_sequencer_test
cmake -B build -S . -G Ninja && cmake --build build --target dbpa_interface_test && ./build/dbpa_interface_test
cmake -B build -S . -G Ninja && cmake --build build --target dbps_api_client_test && ./build/dbps_api_client_test
cmake -B build -S . -G Ninja && cmake --build build --target dbpa_rpc_test && ./build/dbpa_rpc_test
```

### Build the tests
```
echo "----- build: json_request_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target json_request_test \
  || { echo "XXXX FAILED: json_request_test"; false; } && echo

echo "----- build: enum_utils_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target enum_utils_test \
  || { echo "XXXX FAILED: enum_utils_test"; false; } && echo

echo "----- build: encryption_sequencer_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target encryption_sequencer_test \
  || { echo "XXXX FAILED: encryption_sequencer_test"; false; } && echo

echo "----- build: dbpa_interface_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target dbpa_interface_test \
  || { echo "XXXX FAILED: dbpa_interface_test"; false; } && echo

echo "----- build: dbps_api_client_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target dbps_api_client_test \
  || { echo "XXXX FAILED: dbps_api_client_test"; false; } && echo

echo "----- build: dbpa_rpc_test -----" && \
cmake -B build -S . -G Ninja && cmake --build build --target dbpa_rpc_test \
  || { echo "XXXX FAILED: dbpa_rpc_test"; false; } && echo
```

### Run the tests
```
echo "----- run: json_request_test -----" && \
./build/json_request_test \
  || { echo "XXXXX FAILED: json_request_test"; false; } && echo

echo "----- run: enum_utils_test -----" && \
./build/enum_utils_test \
  || { echo "XXXXX FAILED: enum_utils_test"; false; } && echo

echo "----- run: encryption_sequencer_test -----" && \
./build/encryption_sequencer_test \
  || { echo "XXXXX FAILED: encryption_sequencer_test"; false; } && echo

echo "----- run: dbpa_interface_test -----" && \
./build/dbpa_interface_test \
  || { echo "XXXXX FAILED: dbpa_interface_test"; false; } && echo

echo "----- run: dbps_api_client_test -----" && \
./build/dbps_api_client_test \
  || { echo "XXXXX FAILED: dbps_api_client_test"; false; } && echo

echo "----- run: dbpa_rpc_test -----" && \
./build/dbpa_rpc_test \
  || { echo "XXXXX FAILED: dbpa_rpc_test"; false; } && echo
```
