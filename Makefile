all: install

install: REBUILD
	go install

test: REBUILD
	go test -v -tags=debug -timeout=180s
test-short: fmt REBUILD
	go test -short -v -tags=debug -timeout=6s

cover: REBUILD
	go test -v -tags=debug -cover -coverprofile=cover.out
	go tool cover -html=cover.out -o=cover.html
	rm cover.out

benchmark: REBUILD
	go test -v -bench=.
