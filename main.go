package main

import (
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
}

func main() {
	// Test the first packet generation of the handshake
	// if err := testHandshakeInitiation(); err != nil {
	//     log.Fatalf("Handshake test failed: %v", err)
	// }

	// Test the full handshake initiation (both sides)
	if err := testFullHandshakeInitiation(); err != nil {
		log.Fatalf("Full handshake test failed: %v", err)
	}

}
