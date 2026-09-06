BINARY := bin/ghost
VERSION ?= 0.3.0-dev
LDFLAGS := -s -w -X github.com/rappidAI-research/rappid-ghost/internal/cli.Version=$(VERSION)
DIST_AMD64 := dist/ghost_$(VERSION)_linux_amd64
DIST_ARM64 := dist/ghost_$(VERSION)_linux_arm64

.PHONY: build dist test race vet fmt check-fmt bench bench-release clean

build:
	go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ghost

dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(DIST_AMD64) ./cmd/ghost
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(DIST_ARM64) ./cmd/ghost
	cd dist && sha256sum "$(notdir $(DIST_AMD64))" "$(notdir $(DIST_ARM64))" > SHA256SUMS

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

check-fmt:
	test -z "$$(gofmt -l .)"

bench: build
	./$(BINARY) bench

bench-release: build
	./$(BINARY) bench --require-all

clean:
	rm -f $(BINARY) $(DIST_AMD64) $(DIST_ARM64) dist/SHA256SUMS
