package usecase

import (
	"context"
	"fmt"
	"log"
	"strconv"

	pb "github.com/Enthreeka/gRPC-nmap/internal/delivery/grpc/netvuln"
	"github.com/Enthreeka/gRPC-nmap/pkg/nmap"
)

type netVulnSerice struct {
	nmap *nmap.Nmap
}

func NewNetVulnGrpcService(nmap *nmap.Nmap) NetVulnService {
	return &netVulnSerice{
		nmap: nmap,
	}
}

func (n *netVulnSerice) CheckVuln(ctx context.Context, req *pb.CheckVulnRequest) (*pb.CheckVulnResponse, error) {

	result, err := n.nmap.Scanner(ctx, req)
	if err != nil {
		log.Printf("error during nmap scan: %v", err)
		return nil, err
	}

	response := &pb.CheckVulnResponse{
		Results: make([]*pb.TargetResult, 0, len(result.Hosts)),
	}

	for _, host := range result.Hosts {
		targetResult := &pb.TargetResult{
			Target:   host.Addresses[0].String(),
			Services: make([]*pb.Service, 0),
		}

		for _, port := range host.Ports {

			service := &pb.Service{
				Name:    port.Service.Name,
				Version: port.Service.Version,
				TcpPort: int32(port.ID),
				Vulns:   make([]*pb.Vulnerability, 0),
			}

			for _, script := range port.Scripts {

				cvssFloat, err := strconv.ParseFloat(script.Output, 32)
				if err != nil {
					log.Printf("failed to convert string to float64: %v", err)
				}

				fmt.Println(script.Output)

				v := &pb.Vulnerability{
					Identifier: script.ID,
					CvssScore:  float32(cvssFloat),
				}

				service.Vulns = append(service.Vulns, v)
			}

			targetResult.Services = append(targetResult.Services, service)
		}
		response.Results = append(response.Results, targetResult)
	}

	return response, nil
}
