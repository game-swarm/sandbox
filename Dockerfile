FROM rust:latest AS build
WORKDIR /app
COPY . .
RUN cargo build --release --locked --offline --bin swarm-sandbox

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/swarm-sandbox /usr/local/bin/swarm-sandbox
CMD ["swarm-sandbox"]
