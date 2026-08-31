.PHONY: generate test cover build build-all

generate:
	protoc -I proto --go_out=. --go_opt=module=github.com/safullin/pro_go_3 --go-grpc_out=. --go-grpc_opt=module=github.com/safullin/pro_go_3 proto/gophkeeper.proto

test:
	go test -race ./...

cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

build:
	mkdir -p bin
	go build -ldflags "-X main.buildVersion=$${VERSION:-dev} -X main.buildDate=$$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.buildCommit=$$(git rev-parse --short HEAD)" -o bin/gophkeeper ./cmd/gophkeeper
	go build -o bin/gophkeeper-server ./cmd/gophkeeper-server

build-all:
	mkdir -p bin
	GOOS=windows GOARCH=amd64 go build -o bin/gophkeeper-windows-amd64.exe ./cmd/gophkeeper
	GOOS=linux GOARCH=amd64 go build -o bin/gophkeeper-linux-amd64 ./cmd/gophkeeper
	GOOS=darwin GOARCH=amd64 go build -o bin/gophkeeper-darwin-amd64 ./cmd/gophkeeper
	GOOS=darwin GOARCH=arm64 go build -o bin/gophkeeper-darwin-arm64 ./cmd/gophkeeper
