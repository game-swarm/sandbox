# sandbox

WASM sandbox component of Swarm. This repository is self-contained and runs sandbox workers that connect to NATS.

## Development

```sh
cargo check
cargo run
```

`NATS_URL` defaults to `nats://127.0.0.1:4222`.

## Verification

```sh
cargo test
```
