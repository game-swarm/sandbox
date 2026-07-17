# sandbox

WASM sandbox component of Swarm. This repository is self-contained and runs sandbox workers that connect to NATS.

## Development

```sh
cargo check
SWARM_SANDBOX_MODE=development SWARM_NATS_AUTH_SECRET=dev-secret cargo run
```

## Configuration

- `SWARM_SANDBOX_MODE` defaults to `production`; use `development` explicitly for local plaintext NATS.
- `NATS_URL` defaults to `nats://127.0.0.1:4222`.
- `NATS_TLS_REQUIRED` enables mandatory NATS TLS; production requires TLS.
- `NATS_CREDENTIALS_FILE` configures a NATS role credentials file; it is required in production.
- `SWARM_NATS_AUTH_SECRET` is required and must match Engine so authenticated tick/deploy envelopes can be verified.
- `SWARM_SANDBOX_NONCE_PATH` stores authenticated NATS request nonces across worker restarts. In development, this defaults to a **private per-user application state directory** (e.g., `$XDG_STATE_HOME/swarm-sandbox` or `~/.local/state/swarm-sandbox`); in production, it **must be set to a path outside `/tmp`**. The worker fails closed if the file cannot be read, parsed, or atomically updated.
- `SANDBOX_HEALTH_ADDR` defaults to `127.0.0.1:8083` and controls the loopback readiness listener.

`GET /healthz` and `GET /readyz` return the same JSON readiness document. They respond with `200` only after both tick and deploy NATS subscriptions are active; otherwise they respond with `503` and identify the unavailable dependencies. Non-`GET` requests return `405`.

## Verification

```sh
cargo test
```
