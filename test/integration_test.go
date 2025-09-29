package test

import (
	"net"
	"testing"
	"time"

	"github.com/drio/miniwg/device"
)

// TestCompleteWireGuardProtocol validates the entire WireGuard implementation end-to-end.
// A single packet successfully traversing from peer1's TUN to peer2's TUN proves:
// - Noise_IK handshake protocol (ephemeral keys, DH, BLAKE2s, ChaCha20Poly1305)
// - Session establishment and key derivation (KDF1/2/3)
// - Event-driven architecture (TUN/UDP readers, main loop, packet queuing)
// - Transport encryption/decryption with session keys
// - Message marshaling, UDP transmission, and cryptographic authentication
// If any component fails, no packet appears on peer2's TUN (fail-closed security).
func TestCompleteWireGuardProtocol(t *testing.T) {
	// Generate keys for both peers first
	peer1Priv, peer1Pub, err := device.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate peer1 keys: %v", err)
	}
	peer2Priv, peer2Pub, err := device.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate peer2 keys: %v", err)
	}

	// Create two MiniWG instances with each other's public keys
	peer1 := createTestPeer(t, 1, peer1Priv, peer1Pub, peer2Pub)
	peer2 := createTestPeer(t, 2, peer2Priv, peer2Pub, peer1Pub)

	// Connect their UDP channels (peer1 output → peer2 input)
	connectUDPChannels(peer1, peer2)

	// Start both peers' event loops
	go peer1.Run()
	go peer2.Run()

	// Give them a moment to start up
	time.Sleep(10 * time.Millisecond)

	// Create a test packet to send through the tunnel
	testPacket := []byte{0x45, 0x00, 0x00, 0x1c} // Basic IP header start

	// Inject packet into peer1's TUN (simulates app sending packet)
	peer1TUN := peer1.TUN().(*MockTUN)
	peer1TUN.InjectPacket(testPacket)

	// Wait for the full round-trip to complete
	peer2TUN := peer2.TUN().(*MockTUN)
	var receivedPacket []byte

	// Poll for up to 1 second for the decrypted packet to arrive
	for range 100 {
		receivedPacket = peer2TUN.ReadInbound()
		if receivedPacket != nil {
			break // Found the decrypted packet!
		}
		time.Sleep(10 * time.Millisecond)
	}

	if receivedPacket == nil {
		t.Fatal("No packet received by peer2 after 1 second")
	}

	// Verify packet content matches
	if len(receivedPacket) != len(testPacket) {
		t.Errorf("Packet length mismatch: expected %d, got %d", len(testPacket), len(receivedPacket))
	}

	for i, b := range testPacket {
		if receivedPacket[i] != b {
			t.Errorf("Packet content mismatch at byte %d: expected %d, got %d", i, b, receivedPacket[i])
		}
	}

	// Clean up - stop event loops and close interfaces
	peer1.Close()
	peer2.Close()
}

// createTestPeer creates a MiniWG instance with mock interfaces
func createTestPeer(t *testing.T, peerNum int, privateKey, publicKey, peerPubKey [32]byte) *device.MiniWG {
	// Create mock interfaces
	mockTUN := NewMockTUN()
	mockUDP := NewMockUDPConn(51820 + peerNum)

	// Create configuration
	config := device.MiniWGConfig{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		PeerKey:    peerPubKey,
		LocalIndex: uint32(0x1000 + peerNum),
		PeerAddr: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 51820 + (3 - peerNum), // peer1 → 51822, peer2 → 51821
		},
	}

	// Use constructor for proper initialization
	return device.NewMiniWG(mockTUN, mockUDP, config)
}

// connectUDPChannels cross-connects two peers' UDP channels
func connectUDPChannels(peer1, peer2 *device.MiniWG) {
	udp1 := peer1.UDP().(*MockUDPConn)
	udp2 := peer2.UDP().(*MockUDPConn)

	// Connect them: peer1 output → peer2 input, peer2 output → peer1 input
	go func() {
		for {
			select {
			case <-peer1.Done():
				return
			case <-peer2.Done():
				return
			default:
				packet := udp1.ReadOutbound()
				if packet == nil {
					time.Sleep(1 * time.Millisecond)
					continue
				}
				udp2.InjectPacket(packet.Data, udp1.localAddr)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-peer1.Done():
				return
			case <-peer2.Done():
				return
			default:
				packet := udp2.ReadOutbound()
				if packet == nil {
					time.Sleep(1 * time.Millisecond)
					continue
				}
				udp1.InjectPacket(packet.Data, udp2.localAddr)
			}
		}
	}()
}
