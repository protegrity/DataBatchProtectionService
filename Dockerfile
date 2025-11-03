FROM docker.io/apache/arrow-dev:arm64v8-ubuntu-22.04-cpp AS arrow-dev-image

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    cmake \
    ninja-build \
    libboost-date-time-dev \
    libboost-system-dev \
    libboost-filesystem-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy all files from local context into Docker container so the built package is fresh.
COPY . .

RUN cmake -B build -S . -G Ninja && \
    cmake --build build --target dbps_api_server

# (For documentation only) Port the application uses for HTTP requests.
EXPOSE 18080
CMD ["./build/dbps_api_server"]
