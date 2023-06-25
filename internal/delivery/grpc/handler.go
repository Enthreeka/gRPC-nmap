package grpc

import (
	"context"
	"log"

	pb "github.com/Enthreeka/gRPC-nmap/internal/delivery/grpc/netvuln"
	"github.com/Enthreeka/gRPC-nmap/internal/usecase"
)

type vulnServer struct {
	usecase usecase.NetVulnService
	pb.UnimplementedNetVulnServiceServer
}

func NewVulnGrpcServerHandler(usecase usecase.NetVulnService) pb.NetVulnServiceServer {
	return &vulnServer{
		usecase: usecase,
	}
}

func (v *vulnServer) CheckVuln(ctx context.Context, req *pb.CheckVulnRequest) (*pb.CheckVulnResponse, error) {

	response, err := v.usecase.CheckVuln(ctx, req)
	if err != nil {
		log.Printf("failed with method in usecase: %v", err)
	}

	return response, nil
}
