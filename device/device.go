package device

import (
	"net"
	"sync"
	"time"

	"github.com/drio/miniwg/conn"
	"github.com/drio/miniwg/tun"
)

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
	mutex sync.RWMutex // Protects handshake and session state

	privateKey [32]byte
	publicKey  [32]byte
	peerKey    [32]byte

	hasSession    bool
	sendKey       [32]byte
	recvKey       [32]byte
	sendNonce     uint64
	recvCounter   uint64
	localIndex    uint32
	peerIndex     uint32
	lastHandshake time.Time

	queuedPackets [][]byte // Packets waiting for session establishment

	initiatorState *HandshakeInitiationState // Used when we initiate handshake
	responderState *HandshakeResponderState  // Used when peer initiates handshake
	isHandshaking  bool                      // Prevent multiple simultaneous attempts

	tun      tun.TUNDevice
	udp      conn.UDPConn
	peerAddr *net.UDPAddr

	rekeyTimer   *time.Timer
	lastSent     time.Time
	lastReceived time.Time

	// Shutdown coordination (minimal approach for learning)
	// Note: WireGuard-Go uses atomic state + WaitGroups + reference counting
	// for production-grade shutdown with proper goroutine coordination and
	// cleanup ordering. This simple approach works for educational purposes.
	done chan struct{}
}

// NewMiniWG creates a new MiniWG instance with proper initialization
func NewMiniWG(tunDev tun.TUNDevice, udpConn conn.UDPConn, config MiniWGConfig) *MiniWG {
	wg := &MiniWG{
		tun:      tunDev,
		udp:      udpConn,
		peerAddr: config.PeerAddr,

		privateKey: config.PrivateKey,
		publicKey:  config.PublicKey,
		peerKey:    config.PeerKey,
		localIndex: config.LocalIndex,

		hasSession:    false,
		isHandshaking: false,
		sendNonce:     0,
		recvCounter:   0,

		// Initialize timer but keep it stopped until session is established
		rekeyTimer: time.NewTimer(REKEY_AFTER_TIME),
		done:       make(chan struct{}),
	}

	// Stop timer initially - will be started when handshake completes
	wg.rekeyTimer.Stop()

	return wg
}

// Public accessors for testing - these expose internal state needed by integration tests
// In production WireGuard, these would not be exposed as they break encapsulation

// TUN returns the TUN device interface for testing
func (wg *MiniWG) TUN() tun.TUNDevice {
	return wg.tun
}

// UDP returns the UDP connection interface for testing
func (wg *MiniWG) UDP() conn.UDPConn {
	return wg.udp
}

// Done returns the done channel for testing shutdown coordination
func (wg *MiniWG) Done() <-chan struct{} {
	return wg.done
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

// queuePacket adds a packet to the queue while waiting for handshake completion
func (wg *MiniWG) queuePacket(packet []byte) {
	packetCopy := make([]byte, len(packet))
	copy(packetCopy, packet)

	wg.queuedPackets = append(wg.queuedPackets, packetCopy)
}

// sendQueuedPackets processes all queued packets after session establishment
func (wg *MiniWG) sendQueuedPackets() {
	if len(wg.queuedPackets) == 0 {
		return
	}

	for _, packet := range wg.queuedPackets {
		wg.handleTunnelTraffic(packet)
	}

	wg.queuedPackets = nil
}
