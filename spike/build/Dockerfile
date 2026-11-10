FROM rust:1.99.1-alpine
# D151: Alpine's system lld, clang and cmake for aws-lc-sys.
RUN apk add --no-cache lld clang build-base cmake perl linux-headers protobuf protobuf-dev
WORKDIR /src
