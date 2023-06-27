package server

import (
	"fmt"
	"net"

	"github.com/Enthreeka/gRPC-nmap/internal/config"
	"github.com/Enthreeka/gRPC-nmap/internal/usecase"
	"github.com/Enthreeka/gRPC-nmap/pkg/logger"
	"github.com/Enthreeka/gRPC-nmap/pkg/nmap"
	"google.golang.org/grpc"

	netvulnGrpc "github.com/Enthreeka/gRPC-nmap/internal/delivery/grpc"
	pb "github.com/Enthreeka/gRPC-nmap/internal/delivery/grpc/netvuln"
)

func Run(log *logger.Logger, cfg *config.Config) error {

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.ServerGrpc.Port))
	if err != nil {
		log.Fatal("failed to listen: %v", err)
		return err
	}

	nmap := nmap.NewNmapScanner(log)

	netVulnService := usecase.NewNetVulnGrpcService(nmap, log)
	vulnGrpcServer := netvulnGrpc.NewVulnGrpcServerHandler(netVulnService, log)

	s := grpc.NewServer()
	pb.RegisterNetVulnServiceServer(s, vulnGrpcServer)

	log.Info("Starting gRPC listener on port :" + cfg.ServerGrpc.Port)
	if err := s.Serve(lis); err != nil {
		log.Fatal("failed to serve: %v", err)
		return err
	}

	return err
}
