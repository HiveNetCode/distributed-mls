FROM gcc

# Dependencies: OpenSSL and nlohmann-json, CMake to build mlspp
RUN apt-get update && \
    apt-get install -y openssl libssl-dev && \
    apt-get install -y nlohmann-json3-dev && \
    apt-get install -y cmake

WORKDIR /app
COPY . .
RUN make
