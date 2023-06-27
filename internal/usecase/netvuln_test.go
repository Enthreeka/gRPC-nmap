package usecase

import (
	"context"
	"log"
	"testing"
	"time"

	pb "github.com/Enthreeka/gRPC-nmap/internal/delivery/grpc/netvuln"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestCheckVuln(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	defer cancel()

	conn, err := grpc.Dial(":50051", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := pb.NewNetVulnServiceClient(conn)

	t.Run("testasp.vulnweb.com", func(t *testing.T) {

		reqTestV2 := &pb.CheckVulnRequest{
			Targets: []string{"testasp.vulnweb.com"},
			TcpPort: []int32{80},
		}

		got, err := c.CheckVuln(ctx, reqTestV2)
		if err != nil {
			t.Fatalf("CheckVuln returned an error: %v", err)
		}

		want := createTestV2()

		if !isEqual(got, want) {
			t.Errorf("Received response differs from expected response")
		}
	})
	t.Run("scanme.nmap.org", func(t *testing.T) {
		reqTestV1 := &pb.CheckVulnRequest{
			Targets: []string{"scanme.nmap.org"},
			TcpPort: []int32{80},
		}

		got, err := c.CheckVuln(ctx, reqTestV1)
		if err != nil {
			t.Fatalf("CheckVuln returned an error: %v", err)
		}

		want := createTestV1()

		if !isEqual(got, want) {
			t.Errorf("Received response differs from expected response")
		}

	})

}

func createTestV2() *pb.CheckVulnResponse {
	vuln := []*pb.Vulnerability{
		{
			Identifier: "CVE-2014-4078",
			CvssScore:  5.1,
		},
	}

	service := &pb.Service{
		Name:    "http",
		Version: "8.5",
		TcpPort: 80,
		Vulns:   vuln,
	}

	targRes := &pb.TargetResult{
		Target:   "44.238.29.244",
		Services: []*pb.Service{service},
	}

	want := &pb.CheckVulnResponse{
		Results: []*pb.TargetResult{targRes},
	}

	return want

}

func createTestV1() *pb.CheckVulnResponse {
	vuln := []*pb.Vulnerability{
		{
			Identifier: "EDB-ID:51193",
			CvssScore:  7.5,
		}, {
			Identifier: "CVE-2023-25690",
			CvssScore:  7.5,
		}, {
			Identifier: "CVE-2022-31813",
			CvssScore:  7.5,
		}, {
			Identifier: "CVE-2022-23943",
			CvssScore:  7.5,
		}, {
			Identifier: "CVE-2022-22720 ",
			CvssScore:  7.5,
		}, {
			Identifier: "CVE-2021-44790 ",
			CvssScore:  7.5,
		}, {
			Identifier: " CVE-2021-39275 ",
			CvssScore:  7.5,
		}, {
			Identifier: "CVE-2021-26691",
			CvssScore:  7.5,
		}, {
			Identifier: "CVE-2017-7679",
			CvssScore:  7.5,
		}, {
			Identifier: "CVE-2017-3167",
			CvssScore:  7.5,
		}, {
			Identifier: "CNVD-2022-73123",
			CvssScore:  7.5,
		}, {
			Identifier: "CNVD-2022-03225",
			CvssScore:  7.5,
		}, {
			Identifier: "CNVD-2021-102386",
			CvssScore:  7.5,
		}, {
			Identifier: "5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9",
			CvssScore:  7.5,
		}, {
			Identifier: "1337DAY-ID-38427",
			CvssScore:  7.5,
		}, {
			Identifier: "PACKETSTORM:127546",
			CvssScore:  6.8,
		}, {
			Identifier: "FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8",
			CvssScore:  6.8,
		}, {
			Identifier: "CVE-2021-40438",
			CvssScore:  6.8,
		}, {
			Identifier: "CVE-2020-35452",
			CvssScore:  6.8,
		}, {
			Identifier: "CVE-2018-1312",
			CvssScore:  6.8,
		}, {
			Identifier: "CVE-2017-15715",
			CvssScore:  6.8,
		}, {
			Identifier: "CVE-2016-5387",
			CvssScore:  6.8,
		},
	}

	service := &pb.Service{
		Name:    "http",
		Version: "2.4.7",
		TcpPort: 80,
		Vulns:   vuln,
	}

	targRes := &pb.TargetResult{
		Target:   "45.33.32.156",
		Services: []*pb.Service{service},
	}

	want := &pb.CheckVulnResponse{
		Results: []*pb.TargetResult{targRes},
	}

	return want
}

func isEqual(got, want *pb.CheckVulnResponse) bool {
	if len(got.Results) != len(want.Results) {
		return false
	}

	for i := 0; i < len(got.Results); i++ {
		if got.Results[i].Target != want.Results[i].Target {
			return false
		}

		if len(got.Results[i].Services) != len(want.Results[i].Services) {
			return false
		}

		for j := 0; j < len(got.Results[i].Services); j++ {
			if got.Results[i].Services[j].Name != want.Results[i].Services[j].Name ||
				got.Results[i].Services[j].Version != want.Results[i].Services[j].Version ||
				got.Results[i].Services[j].TcpPort != want.Results[i].Services[j].TcpPort {
				return false
			}

			if !areVulnerabilitiesEqual(got.Results[i].Services[j].Vulns, want.Results[i].Services[j].Vulns) {
				return false
			}
		}
	}

	return true
}

func areVulnerabilitiesEqual(got, want []*pb.Vulnerability) bool {
	if len(got) != len(want) {
		return false
	}

	for i := 0; i < len(got); i++ {
		if got[i].Identifier != want[i].Identifier || got[i].CvssScore != want[i].CvssScore {
			return false
		}
	}

	return true
}
