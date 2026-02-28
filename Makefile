VERSION ?= dev
# Path to the org's EC P-256 public key PEM file.
# Usage: make build-prod ORG_PUBLIC_KEY_PEM_FILE=org_pubkey.pem VERSION=1.0.0
ORG_PUBLIC_KEY_PEM_FILE ?=

# Convert the PEM file's real newlines to literal \n so ldflags can embed it
# as a single-line string. main.go unescapes \n back to real newlines at startup.
_PEM_ESCAPED := $(if $(ORG_PUBLIC_KEY_PEM_FILE),$(shell awk 'BEGIN{ORS="\\n"} 1' "$(ORG_PUBLIC_KEY_PEM_FILE)"),)

LDFLAGS := -X 'main.orgPublicKeyPEM=$(_PEM_ESCAPED)' \
           -X 'main.version=$(VERSION)'

# ── Development ───────────────────────────────────────────────

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o bin/sentinel ./cmd/sentinel

.PHONY: test
test:
	go test ./... -v -count=1

.PHONY: lint
lint:
	go vet ./...

# ── Production (garble-obfuscated) ────────────────────────────

.PHONY: build-prod
build-prod:
	garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel ./cmd/sentinel

# ── Cross-compilation (garble, all 5 platforms) ───────────────

.PHONY: build-linux-amd64
build-linux-amd64:
	GOOS=linux GOARCH=amd64 garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel-linux-amd64 ./cmd/sentinel

.PHONY: build-linux-arm64
build-linux-arm64:
	GOOS=linux GOARCH=arm64 garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel-linux-arm64 ./cmd/sentinel

.PHONY: build-darwin-arm64
build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel-darwin-arm64 ./cmd/sentinel

.PHONY: build-windows-amd64
build-windows-amd64:
	GOOS=windows GOARCH=amd64 garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel-windows-amd64.exe ./cmd/sentinel

.PHONY: build-windows-arm64
build-windows-arm64:
	GOOS=windows GOARCH=arm64 garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel-windows-arm64.exe ./cmd/sentinel

.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64 build-darwin-arm64 \
           build-windows-amd64 build-windows-arm64

# ── Utility ───────────────────────────────────────────────────

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: deps
deps:
	go mod tidy
