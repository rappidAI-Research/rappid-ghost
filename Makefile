BINARY := bin/ghost

.PHONY: build test race vet fmt check-fmt bench bench-release clean

build:
	go build -o $(BINARY) ./cmd/ghost

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
	rm -f $(BINARY)
