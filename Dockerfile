FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p depguard-server

FROM debian:bookworm-slim
COPY --from=build /src/target/release/depguard-server /usr/local/bin/depguard-server
EXPOSE 8080
CMD ["depguard-server"]
