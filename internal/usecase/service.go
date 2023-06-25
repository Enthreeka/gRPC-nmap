package usecase

import (
	"context"

	pb "github.com/Enthreeka/gRPC-nmap/internal/delivery/grpc/netvuln"
)

type NetVulnService interface {
	CheckVuln(context.Context, *pb.CheckVulnRequest) (*pb.CheckVulnResponse, error)
}
