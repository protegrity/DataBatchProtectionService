# Data Batch Protection Service

## Building the server docker image

```
$ docker build -t dbps_server .
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
$ docker build -t dbps_server .
```

Run docker container with source files mounted:
```
$ docker run -it --rm  -v $(pwd):/app  -p 18080:18080  dbps_server /bin/bash
```

Make changes to source files as needed.

Then build and run manually from inside the docker container bash
```
# cmake -B build -S . -G Ninja && cmake --build build --target dbps_api_server
# ./build/dbps_api_server
```

