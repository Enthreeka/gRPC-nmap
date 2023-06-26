package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/Enthreeka/gRPC-nmap/internal/config"
	pb "github.com/Enthreeka/gRPC-nmap/internal/delivery/grpc/netvuln"
	"google.golang.org/grpc"
)

func main() {

	configPath := "C:/Users/world/go-workspace/gRPC-nmap/configs/config.json"

	cfg, err := config.New(configPath)
	if err != nil {
		log.Printf("failed to load config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	defer cancel()

	conn, err := grpc.Dial(cfg.ClientGrpc.Port, grpc.WithInsecure(), grpc.WithBlock())

	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := pb.NewNetVulnServiceClient(conn)

	request := &pb.CheckVulnRequest{
		Targets: []string{"scanme.nmap.org"},
		TcpPort: []int32{80},
	}

	r, err := c.CheckVuln(ctx, request)
	if err != nil {
		log.Printf("failed to get response from server: %v", err)
	}

	result := r.GetResults()

	resultByte, err := json.MarshalIndent(&result, " ", " ")
	if err != nil {
		log.Printf("unable to marshaling response struct: %v", err)
	}

	log.Printf("Results: %s", resultByte)

}
