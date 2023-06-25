	package main

	import (
		"context"
		"encoding/json"
		"fmt"
		"log"
		"time"

		pb "github.com/Enthreeka/gRPC-nmap/internal/delivery/grpc/netvuln"
		"google.golang.org/grpc"
	)

	const (
		address = "localhost:50051"
	)

	func main() {

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		defer cancel()

		conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())

		if err != nil {
			log.Fatalf("did not connect: %v", err)
		}
		defer conn.Close()

		c := pb.NewNetVulnServiceClient(conn)

		request := &pb.CheckVulnRequest{
			Targets: []string{"31.13.81.36", "172.217.16.46", "216.58.215.110"},
			TcpPort: int32(80),
		}

		response, err := c.CheckVuln(ctx, request)
		if err != nil {
			log.Printf("failed to get response from server: %v", err)
		}

		responseByte, err := json.MarshalIndent(&response, " ", " ")
		if err != nil {
			log.Printf("unable to marshaling response struct: %v", err)
		}

		fmt.Printf(string(responseByte))

	}
