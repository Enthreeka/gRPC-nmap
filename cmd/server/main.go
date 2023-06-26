package main

import (
	"github.com/Enthreeka/gRPC-nmap/internal/config"
	"github.com/Enthreeka/gRPC-nmap/internal/server"
	"github.com/Enthreeka/gRPC-nmap/pkg/logger"
)

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
