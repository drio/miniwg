package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/songgao/water"
	"golang.org/x/crypto/curve25519"
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

// loadConfig reads configuration from a file
func (wg *MiniWG) loadConfig(configFile string) error {
	file, err := os.Open(configFile)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "PrivateKey":
			privateKeyBytes, err := hex.DecodeString(value)
			if err != nil {
				return fmt.Errorf("failed to decode private key: %v", err)
			}
			copy(wg.privateKey[:], privateKeyBytes)

		case "PeerPublicKey":
			peerKeyBytes, err := hex.DecodeString(value)
			if err != nil {
				return fmt.Errorf("failed to decode peer key: %v", err)
			}
			copy(wg.peerKey[:], peerKeyBytes)

		case "ListenPort":
			port, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("failed to parse listen port: %v", err)
			}
			wg.listenPort = port

		case "PeerEndpoint":
			peerAddr, err := net.ResolveUDPAddr("udp", value)
			if err != nil {
				return fmt.Errorf("failed to resolve peer address: %v", err)
			}
			wg.peerAddr = peerAddr

		case "TunName":
			wg.tunName = value

		case "TunAddress":
			wg.tunAddress = value
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	// Derive public key from private key
	curve25519.ScalarBaseMult(&wg.publicKey, &wg.privateKey)

	// Generate random local index for this session
	wg.localIndex = 0x12345678

	log.Printf("Local public key: %x", wg.publicKey)
	log.Printf("Peer public key: %x", wg.peerKey)
	log.Printf("Listen port: %d", wg.listenPort)
	log.Printf("Peer address: %s", wg.peerAddr)
	log.Printf("TUN: %s (%s)", wg.tunName, wg.tunAddress)

	return nil
}

// setupUDP creates and binds the UDP socket for WireGuard communication
func (wg *MiniWG) setupUDP() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", wg.listenPort))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind UDP socket: %v", err)
	}

	wg.udp = conn
	log.Printf("UDP socket listening on port %d", wg.listenPort)
	return nil
}

func main() {
	log.Println("MiniWG - Minimal WireGuard Implementation")

	// Parse command line flags
	configFile := flag.String("c", "", "Configuration file path")
	flag.Parse()

	if *configFile == "" {
		log.Fatal("Usage: miniwg -c <config-file>")
	}

	wg := &MiniWG{}

	// Load configuration from file
	if err := wg.loadConfig(*configFile); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Setup UDP socket
	if err := wg.setupUDP(); err != nil {
		log.Fatalf("Failed to setup UDP socket: %v", err)
	}

	fmt.Println("Configuration loaded successfully")
	fmt.Println("TODO: Setup TUN interface")
}
