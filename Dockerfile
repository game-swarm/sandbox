FROM rust:latest AS build
WORKDIR /app
COPY sandbox ./sandbox
WORKDIR /app/sandbox
RUN cargo build --release --bin swarm-sandbox

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/sandbox/target/release/swarm-sandbox /usr/local/bin/swarm-sandbox
CMD ["swarm-sandbox"]
