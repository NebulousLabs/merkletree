all: install

fmt:
	go fmt ./...

REBUILD:
	@touch debug*.go

install: fmt REBUILD
	go install ./...

dependencies:
	go install -race std

test: fmt REBUILD
	go test -v -race -tags=debug -timeout=60s ./...

benchmark: fmt REBUILD
	go test -run=XXX -v -bench=.
