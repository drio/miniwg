package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/drio/miniwg/config"
	"github.com/drio/miniwg/conn"
	"github.com/drio/miniwg/device"
	"github.com/drio/miniwg/tun"
)

func main() {
	log.Println("MiniWG - Minimal WireGuard Implementation")

	configFile := flag.String("c", "", "Configuration file path")
	flag.Parse()

	if *configFile == "" {
		log.Fatal("Usage: miniwg -c <config-file>")
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	udpConn, err := conn.SetupUDP(cfg.ListenPort)
	if err != nil {
		log.Fatalf("Failed to setup UDP socket: %v", err)
	}

	tunDev, err := tun.SetupTUN(cfg.TunName, cfg.TunAddress)
	if err != nil {
		log.Fatalf("Failed to setup TUN interface: %v", err)
	}

	deviceConfig := device.MiniWGConfig{
		PrivateKey: cfg.PrivateKey,
		PublicKey:  cfg.PublicKey,
		PeerKey:    cfg.PeerKey,
		LocalIndex: cfg.LocalIndex,
		PeerAddr:   cfg.PeerAddr,
	}

	wg := device.NewMiniWG(tunDev, udpConn, deviceConfig)
	defer wg.Close()

	fmt.Println("Network interfaces initialized successfully")
	fmt.Println("Starting main event loop...")

	wg.Run()
}
