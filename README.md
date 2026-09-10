# qday-pqc-sdk

Go SDK for post-quantum **sign** and **verify**, using [liboqs-go](https://github.com/open-quantum-safe/liboqs-go) (ML-DSA / FIPS 204).

```
pqc/            keygen, sign, verify, encodings
examples/sign/  local sign/verify sample
```

## Install

Requires Go 1.23+, CGO, and a system [liboqs](https://github.com/open-quantum-safe/liboqs) 0.16 install (`brew install liboqs pkgconf` on macOS).

```bash
go get github.com/qday-io/qday-pqc-sdk
```

On macOS, `make` sets `PKG_CONFIG_PATH` to `.config/` so liboqs-go can find Homebrew liboqs.

## Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/qday-io/qday-pqc-sdk/pqc"
)

func main() {
	signer, err := pqc.Generate(pqc.AlgMLDSA65)
	if err != nil {
		log.Fatal(err)
	}
	defer signer.Clean()

	msg := []byte("hello pqc")
	sig, err := signer.Sign(msg)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := pqc.Verify(signer.Algorithm(), msg, sig, signer.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ok)
}
```

Rebuild a signer from existing key bytes with `pqc.New(alg, secretKey, publicKey)`. Verify against a public key only with `pqc.NewVerifier`.

| API | Description |
| --- | --- |
| `pqc.Generate` | New key pair |
| `pqc.New` | Reconstruct from secret and public key bytes |
| `(*Signer).Sign` | Detached signature |
| `(*Signer).Clean` | Zero the in-memory secret key |
| `pqc.Verify` / `pqc.NewVerifier` | Verify a signature |
| `pqc.EncodeBase64` / `DecodeBase64` | RFC 4648 encodings for keys and signatures |
| `pqc.EnabledAlgorithms` | Signature names enabled in this liboqs build |

```bash
make test
make example
```

## Algorithms

Must be a signature algorithm **enabled in liboqs 0.16**. Default is `ML-DSA-65`.

**Recommended — ML-DSA (FIPS 204)**

| Constant | Value | NIST category | Notes |
| --- | --- | --- | --- |
| `pqc.AlgMLDSA44` | `ML-DSA-44` | 2 | Smaller keys/signatures |
| `pqc.AlgMLDSA65` | `ML-DSA-65` | 3 | Default |
| `pqc.AlgMLDSA87` | `ML-DSA-87` | 5 | Highest of the three |

Also commonly used: `pqc.AlgFalcon512`, `pqc.AlgFalcon1024`.

**Also enabled in this liboqs build** (exact names, case-sensitive):

- Falcon: `Falcon-512`, `Falcon-1024`, `Falcon-padded-512`, `Falcon-padded-1024`
- MAYO: `MAYO-1`, `MAYO-2`, `MAYO-3`, `MAYO-5`
- CROSS: `cross-rsdp-{128,192,256}-{balanced,fast,small}`, `cross-rsdpg-{128,192,256}-{balanced,fast,small}`
- UOV: `OV-{Is,Ip,III,V}` and `-pkc` / `-pkc-skc` variants
- SNOVA: `SNOVA_24_5_4`, `SNOVA_24_5_4_SHAKE`, `SNOVA_24_5_4_esk`, `SNOVA_24_5_4_SHAKE_esk`, `SNOVA_37_17_2`, `SNOVA_25_8_3`, `SNOVA_56_25_2`, `SNOVA_49_11_3`, `SNOVA_37_8_4`, `SNOVA_24_5_5`, `SNOVA_60_10_4`, `SNOVA_29_6_5`
- MQOM: `mqom2_cat{1,3,5}_gf16_{fast,short}_r{3,5}`
- SLH-DSA (FIPS 205): `SLH_DSA_PURE_SHA2_{128,192,256}{S,F}`, `SLH_DSA_PURE_SHAKE_{128,192,256}{S,F}`, plus many `SLH_DSA_*_PREHASH_*` names

List names at runtime with `pqc.EnabledAlgorithms()`. An unknown name fails at keygen. Dilithium and SPHINCS+ names are **not** valid in liboqs 0.16.

## Local (macOS)

Prerequisites: Go 1.23+, `brew install liboqs pkgconf`.

```bash
make test
make example
```
