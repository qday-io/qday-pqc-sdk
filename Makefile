PKG_CONFIG_PATH := $(CURDIR)/.config
CGO_ENABLED := 1
# Homebrew liboqs bottles target macOS 26; Go's default min version is older.
MACOSX_DEPLOYMENT_TARGET := 26.0
CGO_CFLAGS := -mmacosx-version-min=26.0
CGO_LDFLAGS := -mmacosx-version-min=26.0
export PKG_CONFIG_PATH
export CGO_ENABLED
export MACOSX_DEPLOYMENT_TARGET
export CGO_CFLAGS
export CGO_LDFLAGS

.PHONY: run test build tidy docker-build docker-run docker-up verify

run:
	go run ./cmd

test:
	go test -v ./...

build:
	go build -o bin/qday-pqc-server ./cmd

tidy:
	go mod tidy

docker-build:
	docker build -t qday-pqc-server:local .

docker-run:
	docker run --rm -p 8080:8080 --name qday-pqc-server qday-pqc-server:local

docker-up:
	docker compose up -d

verify:
	./scripts/verify-api.sh
