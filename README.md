# Data Batch Protection Service

## Table of Contents
- [API server](#api-server)
- [Development Dockerfile](#development-dockerfile)
- [Building the server docker image](#building-the-server-docker-image)
- [Running the server locally from the docker image](#running-the-server-locally-from-the-docker-image)
- [For development](#for-development)
- [Running Unittests](#running-unittests)
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

Run docker container with source files mounted and open up a shell:
```
$ docker run -it --rm  -v $(pwd):/app  -p 18080:18080  dbps_server /bin/bash
```

Make changes to source files as needed.

Then build and run manually from inside the docker container bash
```
# Build server
$ cmake -B build -S . -G Ninja && cmake --build build --target dbps_api_server

# then run it interactively
$ ./build/dbps_api_server

# .. or in the background with a logfile output
$ ./build/dbps_api_server > dbps_api_server_RUN.log 2>&1 &
```

## Running Unittests

The project includes unit tests. To run the tests:

### Build and running the tests
```
# First, open up a shell within the docker container with source files mounted (instructions above)
# Second, inside the container, build the tests

$ cd /app
$ cmake --build build --target tests

# Third, run the tests (the -j parameter indicates parallelism)
$ ctest --test-dir build -j 8
```

## Running DBPA remote testing app
```
# First, run docker container with source files mounted (instructions above)
# Then, inside the container...

# Build the application
$ cd /app
$ cmake -B build -S . -G Ninja && cmake --build build --target dbpa_remote_testapp

# Run the application
$ ./build/dbpa_remote_testapp
$ ./build/dbpa_remote_testapp --server_url=http://18.222.202.51:45001
$ ./build/dbpa_remote_testapp --help
```
