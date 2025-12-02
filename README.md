# grpc-passthrough

A lightweight HTTP wrapper around the standard `grpc.health.v1.Health/Check` RPC.
Send the target `host:port` plus request metadata and the server will proxy the
health check and return the result.

## Setup

```bash
bun install
```

## Run the server

```bash
bun run index.ts
```

The server defaults to port `3000`. Use `PORT=8080 bun run index.ts` to override.

## Usage

`POST /health/check` with a JSON body:

```json
{
  "target": "user.dev.v2.nobi.id:443",
  "service": "",
  "insecure": false,
  "metadata": [
    { "key": "X-Client-ID", "value": "your-client-id" },
    { "key": "Authorization", "value": "Bearer your-token" }
  ]
}
```

Fields:
- `target` (or `host`): required, `host:port` of the gRPC server.
- `service`: optional, health service name to check (empty string for default).
- `insecure`: optional, set `true` to use plaintext instead of TLS.
- `metadata`: optional array of `{ key, value }` items to forward as gRPC metadata.
  - If you include `client-key`, the server will remove it and generate
    `Authorization: TOTP <hmac>` where `<hmac>` is an HMAC-SHA256 of the current
    epoch (rounded to 30s) using `client-key` as the secret. Any existing
    `Authorization` entry will be replaced.

Response will be `200` when the service is `SERVING`, otherwise `503`. Errors
from the gRPC call are returned with status `502` and include the gRPC code and
details when available.

## Tips / troubleshooting

- Health `service` name: most servers expect an empty string. Only set a name if
  the target registers per-service health checks.
- TLS vs plaintext: If your target is plaintext (common on non-443 ports), set
  `"insecure": true`. TLS against a non-TLS endpoint will fail with transport
  errors such as `h2 is not supported`.
- Metadata comments: The VS Code REST client does not allow inline comments
  inside JSON bodies. Remove trailing comments when sending (they are kept in
  `health-check.http` only for illustration).
