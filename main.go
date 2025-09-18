package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/songgao/water"
)

// MiniWG represents a minimal WireGuard implementation
type MiniWG struct {
	// Static keys
	privateKey [32]byte
	publicKey  [32]byte
	peerKey    [32]byte

	// Session state
	hasSession    bool
	sendKey       [32]byte
	recvKey       [32]byte
	sendNonce     uint64
	recvCounter   uint64
	localIndex    uint32
	peerIndex     uint32
	lastHandshake time.Time

	// Network interfaces
	tun      *water.Interface
	udp      *net.UDPConn
	peerAddr *net.UDPAddr

	// Basic timers
	rekeyTimer   *time.Timer
	lastSent     time.Time
	lastReceived time.Time

	// Configuration
	listenPort int
	tunName    string
	tunAddress string
}

func main() {
	log.Println("MiniWG - Minimal WireGuard Implementation")

	configFile := flag.String("c", "", "Configuration file path")
	flag.Parse()

	if *configFile == "" {
		log.Fatal("Usage: miniwg -c <config-file>")
	}

	wg := &MiniWG{}

	if err := wg.loadConfig(*configFile); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := wg.setupUDP(); err != nil {
		log.Fatalf("Failed to setup UDP socket: %v", err)
	}

	if err := wg.setupTUN(); err != nil {
		log.Fatalf("Failed to setup TUN interface: %v", err)
	}

	// Initialize rekey timer but keep it stopped until session is established
	// We create the timer now so it's ready to use, but stop it immediately
	// to prevent firing during startup. It will be started when handshake completes.
	wg.rekeyTimer = time.NewTimer(REKEY_AFTER_TIME)
	wg.rekeyTimer.Stop()

	fmt.Println("Network interfaces initialized successfully")
	fmt.Println("Starting main event loop...")

	wg.run()
}
