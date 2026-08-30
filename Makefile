BINARY := bin/ghost

.PHONY: build test vet fmt check-fmt clean

build:
	go build -o $(BINARY) ./cmd/ghost

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

check-fmt:
	test -z "$$(gofmt -l .)"

clean:
	rm -f $(BINARY)
