# qday-pqc-server

Go HTTP service for post-quantum **sign** and **verify**, using [liboqs-go](https://github.com/open-quantum-safe/liboqs-go) (ML-DSA / FIPS 204).

## API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Liveness |
| `GET` | `/v1/info` | Algorithm, public key, liboqs version |
| `POST` | `/v1/sign` | Sign with the server private key |
| `POST` | `/v1/verify` | Verify a signature |

Sign:

```bash
curl -sS http://127.0.0.1:8080/v1/sign \
  -H 'Content-Type: application/json' \
  -d '{"message":"hello pqc"}'
```

```json
{
  "algorithm": "ML-DSA-65",
  "signature_b64": "...",
  "public_key_b64": "..."
}
```

Verify (omit `public_key_b64` to use the server public key):

```bash
curl -sS http://127.0.0.1:8080/v1/verify \
  -H 'Content-Type: application/json' \
  -d '{"message":"hello pqc","signature_b64":"...","public_key_b64":"..."}'
```

Binary payloads: send `message_b64` instead of `message`.

## Configuration

Load order: **defaults → YAML file → environment variables** (env wins).

Config file (`-config` or `PQC_CONFIG`, otherwise `./config.yaml` if present):

```yaml
http_addr: ":8080"
algorithm: ML-DSA-65
log_level: info
secret_key_file: ""
public_key_file: ""
```

| YAML | Env | Default |
| --- | --- | --- |
| `http_addr` | `PQC_HTTP_ADDR` | `:8080` |
| `algorithm` | `PQC_ALGORITHM` | `ML-DSA-65` |
| `log_level` | `PQC_LOG_LEVEL` | `info` |
| `secret_key_file` | `PQC_SECRET_KEY_FILE` | empty (in-memory key) |
| `public_key_file` | `PQC_PUBLIC_KEY_FILE` | empty (in-memory key) |
| — | `PQC_CONFIG` | `./config.yaml` if it exists |

`secret_key_file` and `public_key_file` must be set together. If both files exist they are loaded; otherwise a new key pair is generated and written.

## Local (macOS)

Prerequisites: Go 1.21+, `brew install liboqs pkgconf`.

```bash
make run
make test
```

## Docker (Linux)

Image is Debian bookworm (`linux/arm64` or `linux/amd64` depending on the host). First build compiles [liboqs](https://github.com/open-quantum-safe/liboqs) 0.16.0.

```bash
make docker-build
docker run --rm -p 8080:8080 qday-pqc-server:local
```

Or:

```bash
docker compose up --build
```

Default container config is `config.docker.yaml` (keys at `/data/secret.key` and `/data/public.key`). Override at runtime with env:

```bash
docker run --rm -p 8080:8080 \
  -e PQC_ALGORITHM=ML-DSA-87 \
  -e PQC_HTTP_ADDR=:8080 \
  -e PQC_LOG_LEVEL=debug \
  -v qday-pqc-server-keys:/data \
  qday-pqc-server:local
```
