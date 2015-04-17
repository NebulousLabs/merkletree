all: install

clean:
	rm cover.html

dependencies:
	go get -u golang.org/x/tools/cmd/cover

fmt:
	go fmt

REBUILD:
	@touch debug*.go

install: fmt REBUILD
	go install

test: fmt REBUILD
	go test -v -tags=debug -timeout=60s
test-short: fmt REBUILD
	go test -short -v -tags=debug -timeout=60s

cover: REBUILD
	go test -v -tags=debug -cover -coverprofile=cover.out
	go tool cover -html=cover.out -o=cover.html
	rm cover.out

benchmark: fmt REBUILD
	go test -run=XXX -v -bench=.
