CGO_ENABLED := 1
# Homebrew liboqs bottles target macOS 26; Go's default min version is older.
MACOSX_DEPLOYMENT_TARGET := 26.0
CGO_CFLAGS := -mmacosx-version-min=26.0
CGO_LDFLAGS := -mmacosx-version-min=26.0
export CGO_ENABLED
export MACOSX_DEPLOYMENT_TARGET
export CGO_CFLAGS
export CGO_LDFLAGS

.PHONY: test example tidy

test:
	go test -v ./...

example:
	go run ./examples/sign

tidy:
	go mod tidy
