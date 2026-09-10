# qday-pqc-sdk

Go SDK for post-quantum **sign** and **verify**. It does not implement the algorithms itself: every `Generate` / `Sign` / `Verify` call goes through [liboqs](https://github.com/open-quantum-safe/liboqs) (C) via [liboqs-go](https://github.com/open-quantum-safe/liboqs-go) v0.16.0 (ML-DSA / FIPS 204).

```
pqc/            keygen, sign, verify, encodings
examples/sign/  local sign/verify sample
```

Any machine or container that **builds or runs** code importing this module must have a matching liboqs shared library. Pure-Go `go get` is not enough.

## liboqs

### What you need

| Piece | Role |
| --- | --- |
| liboqs **0.16.x** | C library (`liboqs.so` / `liboqs.dylib`) that performs keygen, sign, verify |
| `oqs/oqs.h` | Headers used at **compile** time (CGO) |
| pkg-config + `liboqs-go.pc` | Tells CGO where those headers and libs are |
| `CGO_ENABLED=1` | Required; this SDK cannot build with CGO off |
| Runtime loader path | Process must find `liboqs` when the binary starts |

Use **liboqs 0.16**, the same series as `liboqs-go v0.16.0`. A different major/minor can fail at link time or reject algorithm names (Dilithium and SPHINCS+ names are not valid in 0.16).

Check the library your process actually loaded:

```go
fmt.Println(pqc.Version())            // liboqs version string
fmt.Println(pqc.EnabledAlgorithms())  // signature names compiled into that build
```

### Install the C library

**macOS (Homebrew)**

```bash
brew install liboqs pkgconf openssl@3
```

Headers and dylib typically land in `/opt/homebrew` (Apple Silicon) or `/usr/local` (Intel).

**Linux (from source, recommended)**

Needs a C compiler, CMake, Ninja or Make, and OpenSSL headers (`libssl-dev` on Debian/Ubuntu).

```bash
git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build liboqs/build --parallel
sudo cmake --install liboqs/build
sudo ldconfig
```

Change `CMAKE_INSTALL_PREFIX` if you cannot install into `/usr/local`. Then use that prefix in `liboqs-go.pc` and in `LD_LIBRARY_PATH`.

### Runtime: finding `liboqs`

Compile-time pkg-config does **not** automatically make the dynamic linker find the library.

| Platform | Typical fix |
| --- | --- |
| Linux | `sudo ldconfig` after install to `/usr/local/lib`, or `export LD_LIBRARY_PATH=/usr/local/lib` |
| macOS Homebrew | Usually works via the dylib install name; if not, `export DYLD_LIBRARY_PATH=/opt/homebrew/lib` |
| Docker | Install liboqs in **both** the build stage (headers + `.so`) and the runtime stage (`.so`). Run `ldconfig` or set `LD_LIBRARY_PATH`. |

If the binary starts and then errors on `liboqs.so.0` / `liboqs.dylib`, the runtime path is wrong, not the Go import.

### CGO: `liboqs-go.pc`

liboqs-go contains `#cgo pkg-config: liboqs-go`. At `go build` / `go test`, pkg-config must resolve a file named `liboqs-go.pc` whose include and lib paths match **this** install. Do not reuse a `.pc` from another machine.

Confirm:

```bash
pkg-config --cflags --libs liboqs-go
```

You should see `-I…/include` and `-L… -loqs`. If pkg-config says the package was not found, `PKG_CONFIG_PATH` is wrong.

**Linux** (liboqs in `/usr/local`): after `go mod download`, liboqs-go already ships a `.pc` for that prefix:

```bash
export PKG_CONFIG_PATH="$(go env GOMODCACHE)/github.com/open-quantum-safe/liboqs-go@v0.16.0/.config${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CGO_ENABLED=1
export LD_LIBRARY_PATH="/usr/local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

**macOS (Homebrew, Apple Silicon):**

```bash
mkdir -p "$HOME/.local/lib/pkgconfig"
cat > "$HOME/.local/lib/pkgconfig/liboqs-go.pc" <<'EOF'
prefix=/opt/homebrew
Name: liboqs-go
Description: Go bindings for liboqs
Version: 0.16.0
Cflags: -I${prefix}/include
Ldflags: '-extldflags "-Wl,-stack_size -Wl,0x1000000"'
Libs: -L${prefix}/lib -loqs -L${prefix}/opt/openssl@3/lib -lcrypto
EOF
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CGO_ENABLED=1
```

On Intel Homebrew, use `prefix=/usr/local`. After changing a `.pc` file, run `go clean -cache` so CGO picks it up.

### Docker / third-party images

Install liboqs in the image (source build as above). Write a `liboqs-go.pc` whose paths match that image prefix. Set `PKG_CONFIG_PATH` and `CGO_ENABLED=1` for the Go build. Copy `liboqs.so*` into the runtime image and run `ldconfig` (or set `LD_LIBRARY_PATH`). You do not copy anything from this repository’s tree for pkg-config.

## Install this SDK

```bash
go get github.com/qday-io/qday-pqc-sdk
```

Requires Go 1.21+ and the liboqs setup above. Then:

```bash
make test
make example
```

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
| `pqc.Generate` | New key pair (liboqs keygen) |
| `pqc.New` | Reconstruct from secret and public key bytes |
| `(*Signer).Sign` | Detached signature (liboqs sign) |
| `(*Signer).Clean` | Zero the in-memory secret key |
| `pqc.Verify` / `pqc.NewVerifier` | Verify a signature (liboqs verify) |
| `pqc.Version` | Linked liboqs version |
| `pqc.EnabledAlgorithms` | Signature names enabled in this liboqs build |
| `pqc.EncodeBase64` / `DecodeBase64` | RFC 4648 encodings for keys and signatures |

The `alg` string must be a name **enabled in the liboqs you linked**. `pqc.Generate("ML-DSA-65")` fails if that mechanism was compiled out.

## Algorithms

Must be a signature algorithm **enabled in liboqs 0.16**. Default is `ML-DSA-65`.

**Recommended — ML-DSA (FIPS 204)**

| Constant | Value | NIST category | Notes |
| --- | --- | --- | --- |
| `pqc.AlgMLDSA44` | `ML-DSA-44` | 2 | Smaller keys/signatures |
| `pqc.AlgMLDSA65` | `ML-DSA-65` | 3 | Default |
| `pqc.AlgMLDSA87` | `ML-DSA-87` | 5 | Highest of the three |

Also commonly used: `pqc.AlgFalcon512`, `pqc.AlgFalcon1024`.

**Also enabled in a typical liboqs 0.16 build** (exact names, case-sensitive):

- Falcon: `Falcon-512`, `Falcon-1024`, `Falcon-padded-512`, `Falcon-padded-1024`
- MAYO: `MAYO-1`, `MAYO-2`, `MAYO-3`, `MAYO-5`
- CROSS: `cross-rsdp-{128,192,256}-{balanced,fast,small}`, `cross-rsdpg-{128,192,256}-{balanced,fast,small}`
- UOV: `OV-{Is,Ip,III,V}` and `-pkc` / `-pkc-skc` variants
- SNOVA: `SNOVA_24_5_4`, `SNOVA_24_5_4_SHAKE`, `SNOVA_24_5_4_esk`, `SNOVA_24_5_4_SHAKE_esk`, `SNOVA_37_17_2`, `SNOVA_25_8_3`, `SNOVA_56_25_2`, `SNOVA_49_11_3`, `SNOVA_37_8_4`, `SNOVA_24_5_5`, `SNOVA_60_10_4`, `SNOVA_29_6_5`
- MQOM: `mqom2_cat{1,3,5}_gf16_{fast,short}_r{3,5}`
- SLH-DSA (FIPS 205): `SLH_DSA_PURE_SHA2_{128,192,256}{S,F}`, `SLH_DSA_PURE_SHAKE_{128,192,256}{S,F}`, plus many `SLH_DSA_*_PREHASH_*` names

List names at runtime with `pqc.EnabledAlgorithms()`. An unknown name fails at keygen. Dilithium and SPHINCS+ names are **not** valid in liboqs 0.16.
