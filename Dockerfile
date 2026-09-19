FROM rust:1.82-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin oid4vc-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/oid4vc-server /usr/local/bin/
EXPOSE 3000
CMD ["oid4vc-server"]
