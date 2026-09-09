# qday-pqc-server

Go HTTP service for post-quantum **sign** and **verify**, using [liboqs-go](https://github.com/open-quantum-safe/liboqs-go) (ML-DSA / FIPS 204).

```
cmd/                   entrypoint
internal/config/       YAML + env loading
internal/signer/       ML-DSA keygen, sign, verify
internal/server/       HTTP handlers and field encodings
configs/               runtime YAML (config.yaml, docker.yaml)
```

## API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Liveness |
| `GET` | `/v1/info` | Algorithm, public key, liboqs version |
| `POST` | `/v1/sign` | Sign with the server private key |
| `POST` | `/v1/verify` | Verify a signature |

All JSON endpoints require `Content-Type: application/json`. Unknown fields are rejected. Body size is limited to 1 MiB. Errors look like `{"error":"..."}`.

**Field encodings**

| Encoding | Used by | Wire format |
| --- | --- | --- |
| UTF-8 | `message` | JSON string, valid UTF-8 |
| RFC 4648 Base64 | `message_b64`, `signature_b64`, `public_key_b64` | Standard alphabet (`+` `/`), padded. Responses always use this. Requests also accept whitespace/newlines, missing padding, and URL-safe (`-` `_`). |
| ASCII | `algorithm` | Algorithm name such as `ML-DSA-65` |

Provide **either** `message` (UTF-8) **or** `message_b64` (Base64 of raw bytes), not both.

### `POST /v1/sign`

Signs with the server private key.

**Request**

| Field | Required | Encoding | Description |
| --- | --- | --- | --- |
| `message` | one of | UTF-8 | Text to sign |
| `message_b64` | one of | RFC 4648 Base64 | Raw bytes to sign |

**Response** (`200`)

| Field | Encoding | Description |
| --- | --- | --- |
| `algorithm` | ASCII | Signature algorithm (e.g. `ML-DSA-65`) |
| `signature_b64` | RFC 4648 Base64 | Detached signature |
| `public_key_b64` | RFC 4648 Base64 | Server public key used for this signature |

**Demo (text)**

```bash
curl -sS http://127.0.0.1:8080/v1/sign \
  -H 'Content-Type: application/json' \
  -d '{"message":"hello pqc"}'
```

```json
{
  "algorithm": "ML-DSA-65",
  "signature_b64": "<base64>",
  "public_key_b64": "<base64>"
}
```

**Demo (binary payload)**

```bash
MSG_B64=$(printf 'hello\x00pqc' | base64)
curl -sS http://127.0.0.1:8080/v1/sign \
  -H 'Content-Type: application/json' \
  -d "{\"message_b64\":\"${MSG_B64}\"}"
```

### `POST /v1/verify`

Verifies a detached signature. Omit `public_key_b64` to use this server's public key. Set `algorithm` only when verifying a key that is not the server's default.

**Request**

| Field | Required | Encoding | Description |
| --- | --- | --- | --- |
| `message` | one of | UTF-8 | Text that was signed |
| `message_b64` | one of | RFC 4648 Base64 | Raw bytes that were signed |
| `signature_b64` | yes | RFC 4648 Base64 | Signature from `/v1/sign` |
| `public_key_b64` | no | RFC 4648 Base64 | Public key; defaults to the server key |
| `algorithm` | no | ASCII | Algorithm; defaults to the server algorithm |

**Response** (`200`)

| Field | Encoding | Description |
| --- | --- | --- |
| `valid` | JSON boolean | `true` if the signature matches the message and public key |

A tampered message still returns `200` with `"valid": false`. Malformed Base64 or missing fields return `400`.

**Demo (verify with returned key)**

```bash
curl -sS http://127.0.0.1:8080/v1/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "message": "hello pqc",
    "signature_b64": "<from sign>",
    "public_key_b64": "<from sign>"
  }'
```

```json
{"valid": true}
```

**Demo (end-to-end, needs `jq`)**

```bash
BASE=http://127.0.0.1:8080

SIGN=$(curl -sS "${BASE}/v1/sign" \
  -H 'Content-Type: application/json' \
  -d '{"message":"hello pqc"}')

echo "$SIGN" | jq .

# Verify with the public key from the sign response
curl -sS "${BASE}/v1/verify" \
  -H 'Content-Type: application/json' \
  -d "$(jq -c '{
    message: "hello pqc",
    signature_b64: .signature_b64,
    public_key_b64: .public_key_b64
  }' <<<"$SIGN")"

# Same message, server public key (omit public_key_b64)
curl -sS "${BASE}/v1/verify" \
  -H 'Content-Type: application/json' \
  -d "$(jq -c '{
    message: "hello pqc",
    signature_b64: .signature_b64
  }' <<<"$SIGN")"

# Tampered message → {"valid":false}
curl -sS "${BASE}/v1/verify" \
  -H 'Content-Type: application/json' \
  -d "$(jq -c '{
    message: "hello pqd",
    signature_b64: .signature_b64,
    public_key_b64: .public_key_b64
  }' <<<"$SIGN")"
```

Get the server public key without signing: `GET /v1/info`.

## Configuration

Load order: **defaults → YAML file → environment variables** (env wins).

Config file (`-config` or `PQC_CONFIG`, otherwise `./config.yaml` or `configs/config.yaml` if present):

```yaml
http_addr: ":8080"
algorithm: ML-DSA-65
log_level: info
secret_key_file: /data/secret.key
public_key_file: /data/public.key
```

Leave `secret_key_file` and `public_key_file` empty for an in-memory key pair (typical for local `make run`).

| YAML | Env | Default |
| --- | --- | --- |
| `http_addr` | `PQC_HTTP_ADDR` | `:8080` |
| `algorithm` | `PQC_ALGORITHM` | `ML-DSA-65` |
| `log_level` | `PQC_LOG_LEVEL` | `info` |
| `secret_key_file` | `PQC_SECRET_KEY_FILE` | empty (in-memory key) |
| `public_key_file` | `PQC_PUBLIC_KEY_FILE` | empty (in-memory key) |
| — | `PQC_CONFIG` | `./config.yaml` or `configs/config.yaml` if it exists |

`secret_key_file` and `public_key_file` must be set together. If both files exist they are loaded; otherwise a new key pair is generated and written.

## Local (macOS)

Prerequisites: Go 1.21+, `brew install liboqs pkgconf`.

```bash
make run
make test
```

## Docker Compose

Uses `ghcr.io/qday-io/qday-pqc-server:main`. Compose bind-mounts host files into the container:

| Host | Container | Purpose |
| --- | --- | --- |
| `./configs/config.yaml` | `/etc/qday-pqc-server/config.yaml` (read-only) | Runtime config |
| `./data` | `/data` | Persistent key files |

### Before starting

1. Edit `configs/config.yaml`. Compose clears image `PQC_*` env vars so this file is the source of truth.

   ```yaml
   http_addr: ":8080"
   algorithm: ML-DSA-65
   log_level: info
   secret_key_file: /data/secret.key
   public_key_file: /data/public.key
   ```

   Paths in YAML are **container** paths. `secret_key_file` and `public_key_file` must be set together.

2. Create the host key directory (Compose will also create it if missing):

   ```bash
   mkdir -p data
   ```

   Do **not** pre-create empty `secret.key` / `public.key` files. If both files are absent, the process generates a key pair on first start and writes `data/secret.key` and `data/public.key`. If both already exist, they are loaded. Key files are gitignored.

3. Pull access to GHCR if the image is private (`docker login ghcr.io`).

### Start

```bash
docker compose up -d
```

Logs and health:

```bash
docker compose logs -f
curl -fsS http://127.0.0.1:8080/health
```

Stop:

```bash
docker compose down
```

`docker compose down` does not delete `./data` keys. After changing `configs/config.yaml`, recreate the container with `docker compose up -d`.

### Build a local image

Image is Debian bookworm. First build compiles [liboqs](https://github.com/open-quantum-safe/liboqs) 0.16.0.

```bash
make docker-build
docker run --rm -p 8080:8080 qday-pqc-server:local
```
