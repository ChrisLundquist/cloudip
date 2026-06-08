.PHONY: build test vet fmt proto cli clean

build: cli

cli:
	go build -o bin/cloudattr ./cmd/cloudattr

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './proto/cloudattrpb/*')

# Regenerate gRPC stubs. Requires protoc, protoc-gen-go, protoc-gen-go-grpc on PATH:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
proto:
	protoc --proto_path=proto \
		--go_out=proto/cloudattrpb --go_opt=paths=source_relative \
		--go-grpc_out=proto/cloudattrpb --go-grpc_opt=paths=source_relative \
		cloudattr.proto

clean:
	rm -rf bin
