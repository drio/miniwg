package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// UDPConn interface for UDP connections - allows mocking for tests
type UDPConn interface {
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
	Close() error
}

// TUNDevice interface for TUN devices - allows mocking for tests
type TUNDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// MiniWGConfig holds configuration for creating a MiniWG instance
type MiniWGConfig struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
	PeerKey    [32]byte
	LocalIndex uint32
	PeerAddr   *net.UDPAddr
}

// MiniWG represents a minimal WireGuard implementation
type MiniWG struct {
	// Concurrency control
	mutex sync.RWMutex // Protects handshake and session state

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

	// Packet queuing during handshake
	queuedPackets [][]byte // Packets waiting for session establishment

	// Handshake state storage
	initiatorState  *HandshakeInitiationState // Used when we initiate handshake
	responderState  *HandshakeResponderState  // Used when peer initiates handshake
	isHandshaking   bool                      // Prevent multiple simultaneous attempts

	// Network interfaces
	tun      TUNDevice
	udp      UDPConn
	peerAddr *net.UDPAddr

	// Basic timers
	rekeyTimer   *time.Timer
	lastSent     time.Time
	lastReceived time.Time

	// Configuration
	listenPort int
	tunName    string
	tunAddress string

	// Shutdown coordination (minimal approach for learning)
	// Note: WireGuard-Go uses atomic state + WaitGroups + reference counting
	// for production-grade shutdown with proper goroutine coordination and
	// cleanup ordering. This simple approach works for educational purposes.
	done chan struct{}
}

// NewMiniWG creates a new MiniWG instance with proper initialization
func NewMiniWG(tun TUNDevice, udp UDPConn, config MiniWGConfig) *MiniWG {
	wg := &MiniWG{
		// Network interfaces
		tun:      tun,
		udp:      udp,
		peerAddr: config.PeerAddr,

		// Keys
		privateKey: config.PrivateKey,
		publicKey:  config.PublicKey,
		peerKey:    config.PeerKey,
		localIndex: config.LocalIndex,

		// Session state
		hasSession:    false,
		isHandshaking: false,
		sendNonce:     0,
		recvCounter:   0,

		// Initialize timer but keep it stopped until session is established
		rekeyTimer: time.NewTimer(REKEY_AFTER_TIME),

		// Initialize shutdown channel
		done: make(chan struct{}),
	}

	// Stop timer initially - will be started when handshake completes
	wg.rekeyTimer.Stop()

	return wg
}

// Close shuts down the MiniWG instance
// Production note: WireGuard-Go uses atomic state management, WaitGroups for
// goroutine coordination, and reference-counted queues to ensure all components
// shut down cleanly without race conditions. This minimal approach works for
// educational purposes but lacks the robustness needed for production use.
func (wg *MiniWG) Close() error {
	close(wg.done)
	if wg.tun != nil {
		wg.tun.Close()
	}
	if wg.udp != nil {
		wg.udp.Close()
	}
	return nil
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

// queuePacket adds a packet to the queue while waiting for handshake completion
func (wg *MiniWG) queuePacket(packet []byte) {
	// Create a copy of the packet to avoid memory issues
	packetCopy := make([]byte, len(packet))
	copy(packetCopy, packet)

	wg.queuedPackets = append(wg.queuedPackets, packetCopy)
	log.Printf("Queued packet (%d bytes) - total queued: %d", len(packet), len(wg.queuedPackets))
}

// sendQueuedPackets processes all queued packets after session establishment
func (wg *MiniWG) sendQueuedPackets() {
	if len(wg.queuedPackets) == 0 {
		return
	}

	log.Printf("Sending %d queued packets", len(wg.queuedPackets))

	for _, packet := range wg.queuedPackets {
		if err := wg.handleTunnelTraffic(packet); err != nil {
			log.Printf("Failed to send queued packet: %v", err)
		} else {
			log.Printf("Sent queued packet (%d bytes)", len(packet))
		}
	}

	// Clear the queue
	wg.queuedPackets = nil
}
