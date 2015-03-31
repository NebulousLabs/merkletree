all: install

fmt:
	go fmt

REBUILD:
	@touch debug*.go

install: fmt REBUILD
	go install

test: fmt REBUILD
	go test -v -tags=debug -timeout=60s

benchmark: fmt REBUILD
	go test -run=XXX -v -bench=.
