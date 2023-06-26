package nmap

import (
	"context"
	"log"
	"strconv"

	pb "github.com/Enthreeka/gRPC-nmap/internal/delivery/grpc/netvuln"
	"github.com/Ullaakut/nmap/v3"
)

type Nmap struct {
}

func NewNmapScanner() *Nmap {
	return &Nmap{}
}

func (n *Nmap) Scanner(ctx context.Context, req *pb.CheckVulnRequest) (*nmap.Run, error) {

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(req.Targets...),
		nmap.WithPorts(intToString(req.TcpPort)...),
		nmap.WithScripts("vulners"),
		//	nmap.WithCustomArguments("-sV"),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings)
	}
	if err != nil {
		log.Printf("unable to run nmap scan: %v", err)
	}

	return result, err
}

func intToString(arr []int32) []string {
	var arrStr []string

	for _, el := range arr {
		strEl := strconv.Itoa(int(el))
		arrStr = append(arrStr, strEl)
	}

	return arrStr
}
