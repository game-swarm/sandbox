# sandbox

WASM sandbox component of Swarm. This repository is self-contained and runs sandbox workers that connect to NATS.

## Development

```sh
cargo check
cargo run
```

`NATS_URL` defaults to `nats://127.0.0.1:4222`.
`SWARM_SANDBOX_NONCE_PATH` defaults to `/tmp/swarm-sandbox-nonces.db` and stores authenticated NATS request nonces across worker restarts. The worker fails closed if the file cannot be read, parsed, or atomically updated.

## Verification

```sh
cargo test
```
