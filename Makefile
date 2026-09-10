CGO_ENABLED := 1
export CGO_ENABLED

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
# Homebrew liboqs bottles may target a newer macOS than Go's default.
MACOSX_DEPLOYMENT_TARGET ?= 26.0
CGO_CFLAGS ?= -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
CGO_LDFLAGS ?= -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
export MACOSX_DEPLOYMENT_TARGET
export CGO_CFLAGS
export CGO_LDFLAGS
endif

.PHONY: test vet example tidy

test:
	go test ./...

vet:
	go vet ./...

example:
	go run ./examples/sign
	go run ./examples/verify

tidy:
	go mod tidy
