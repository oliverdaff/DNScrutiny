## Use cross build --target x86_64-unknown-linux-musl --release to build the binary.
FROM rust:1.45.0 AS build
COPY target/x86_64-unknown-linux-musl/release/dnscrutiny .
RUN strip dnscrutiny

FROM scratch
COPY  --from=build dnscrutiny .
USER 1000
ENTRYPOINT ["./dnscrutiny"]