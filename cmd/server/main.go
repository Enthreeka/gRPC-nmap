package main

import (
	"github.com/Enthreeka/gRPC-nmap/internal/config"
	"github.com/Enthreeka/gRPC-nmap/internal/server"
	"github.com/Enthreeka/gRPC-nmap/pkg/logger"
)

// const (
// 	port = ":50051"
// )

// type Server struct {
// 	pb.UnimplementedNetVulnServiceServer
// }

// func (s *Server) CheckVuln(ctx context.Context, request *pb.CheckVulnRequest) (*pb.CheckVulnResponse, error) {

// 	tcpPortStr := strconv.Itoa(int(request.TcpPort))

// 	scanner, err := nmap.NewScanner(
// 		ctx,
// 		nmap.WithTargets(request.Targets...),
// 		nmap.WithPorts(tcpPortStr),
// 	)
// 	if err != nil {
// 		log.Fatalf("unable to create nmap scanner: %v", err)
// 	}

// 	result, warnings, err := scanner.Run()
// 	if len(*warnings) > 0 {
// 		log.Printf("run finished with warnings: %s\n", *warnings)
// 	}
// 	if err != nil {
// 		log.Printf("unable to run nmap scan: %v", err)
// 	}

// 	response := &pb.CheckVulnResponse{
// 		Results: make([]*pb.TargetResult, 0, len(result.Hosts)),
// 	}

// 	for _, host := range result.Hosts {
// 		targetResult := &pb.TargetResult{
// 			Target:   host.Addresses[0].String(),
// 			Services: make([]*pb.Service, 0),
// 		}

// 		for _, port := range host.Ports {
// 			service := &pb.Service{
// 				Name:    port.Service.Name,
// 				Version: port.Service.Version,
// 				TcpPort: int32(port.ID),
// 				Vulns:   make([]*pb.Vulnerability, 0),
// 			}

// 			for _, vuln := range port.Scripts {
// 				v := &pb.Vulnerability{
// 					Identifier: vuln.ID,
// 					CvssScore:  1.4,
// 				}

// 				service.Vulns = append(service.Vulns, v)
// 			}

// 			targetResult.Services = append(targetResult.Services, service)
// 		}

// 		response.Results = append(response.Results, targetResult)
// 	}

// 	return response, nil
// }

// func main() {

// 	lis, err := net.Listen("tcp", port)
// 	if err != nil {
// 		log.Fatalf("failed to listen: %v", err)
// 	}

// 	s := grpc.NewServer()
// 	pb.RegisterNetVulnServiceServer(s, &Server{})

// 	log.Printf("Starting gRPC listener on port " + port)
// 	if err := s.Serve(lis); err != nil {
// 		log.Fatalf("failed to serve: %v", err)
// 	}
// }

func main() {

	log := logger.New()

	configPath := "C:/Users/world/go-workspace/gRPC-nmap/configs/config.json"

	cfg, err := config.New(configPath)
	if err != nil {
		log.Error("failed to load config: %v", err)
	}

	if err := server.Run(log, cfg); err != nil {
		log.Fatal("failed to run server: %v", err)
	}
}
