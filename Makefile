build:
	go build -o bin/netvuln main.go

lint:
	golangci-lint run

test:
	go test  ./internal/usecase/netvuln_test.go
	
server:
	go run ./cmd/server/main.go
	
client:
	go run ./cmd/client/main.go
