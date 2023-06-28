# gRPC-nmap

This project is gRPC service a wrapper over Nmap for API which containts in ```gRPC-nmap\api\nmap\v1\netvuln.proto```.

## Nmap
The principe of job vulners in [Nmap](https://github.com/vulnersCom/nmap-vulners).

### The command used for search vulnerables:
```
nmap -sV -p 80 --script vulners testasp.vulnweb.com
```
### How install 

[Instrcution.](https://nmap.org/download.html)

## Linter

### Command for get in IDE:
```
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

## Command for use service:

Creating a binary file:
```
make build
```
Running the server:
```
make server
```
Running the client:
````
make client
````
Running the [linters](https://golangci-lint.run/):
````
make lint
````
Running test:
```
make test
```