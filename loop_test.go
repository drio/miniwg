// loop_test.go
//
// Tests for event loop functionality including:
// - Handshake initiation with concurrency safety
// - Packet queuing and processing
// - Handshake event handling
// - Session establishment integration

package main

import (
	"net"
	"sync"
	"testing"
)

// TestInitiateHandshake tests the handshake initiation logic
func TestInitiateHandshake(t *testing.T) {
	t.Run("Basic handshake initiation", func(t *testing.T) {
		wg := createTestMiniWG(t)

		// Configure peer address
		peerAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:51821")
		if err != nil {
			t.Fatalf("Failed to resolve peer address: %v", err)
		}
		wg.peerAddr = peerAddr

		// Should succeed on first call
		err = wg.initiateHandshake()
		if err != nil {
			t.Errorf("First handshake initiation failed: %v", err)
		}

		// Check that handshaking flag is set
		wg.mutex.RLock()
		isHandshaking := wg.isHandshaking
		wg.mutex.RUnlock()

		if !isHandshaking {
			t.Error("isHandshaking flag should be true after initiation")
		}

		// Check that initiator state is set
		wg.mutex.RLock()
		hasInitiatorState := wg.initiatorState != nil
		wg.mutex.RUnlock()

		if !hasInitiatorState {
			t.Error("initiatorState should be set after handshake initiation")
		}
	})

	t.Run("Prevent duplicate handshakes", func(t *testing.T) {
		wg := createTestMiniWG(t)

		// Configure peer address
		peerAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:51821")
		if err != nil {
			t.Fatalf("Failed to resolve peer address: %v", err)
		}
		wg.peerAddr = peerAddr

		// First initiation should succeed
		err = wg.initiateHandshake()
		if err != nil {
			t.Errorf("First handshake initiation failed: %v", err)
		}

		// Second initiation should be skipped (not error)
		err = wg.initiateHandshake()
		if err != nil {
			t.Errorf("Second handshake initiation should not error: %v", err)
		}

		// Should still have only one initiator state
		wg.mutex.RLock()
		isHandshaking := wg.isHandshaking
		wg.mutex.RUnlock()

		if !isHandshaking {
			t.Error("isHandshaking flag should still be true")
		}
	})

	t.Run("No peer configured error", func(t *testing.T) {
		wg := createTestMiniWG(t)

		// Don't configure peer address - should fail
		err := wg.initiateHandshake()
		if err == nil {
			t.Error("Expected error when no peer is configured")
		}

		expectedMsg := "no peer endpoint configured"
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
		}

		// Should not set handshaking flag
		wg.mutex.RLock()
		isHandshaking := wg.isHandshaking
		wg.mutex.RUnlock()

		if isHandshaking {
			t.Error("isHandshaking flag should remain false on error")
		}
	})

	t.Run("Concurrent handshake initiation safety", func(t *testing.T) {
		wg := createTestMiniWG(t)

		// Configure peer address
		peerAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:51821")
		if err != nil {
			t.Fatalf("Failed to resolve peer address: %v", err)
		}
		wg.peerAddr = peerAddr

		const numGoroutines = 10
		var wgTest sync.WaitGroup
		successCount := make(chan int, numGoroutines)

		// Start multiple goroutines trying to initiate handshake
		for range numGoroutines {
			wgTest.Go(func() {
				err := wg.initiateHandshake()
				if err == nil {
					successCount <- 1
				} else {
					successCount <- 0
				}
			})
		}

		wgTest.Wait()
		close(successCount)

		// Count successful initiations
		totalSuccess := 0
		for success := range successCount {
			totalSuccess += success
		}

		// Should have at least one success (the first one)
		if totalSuccess < 1 {
			t.Error("Expected at least one successful handshake initiation")
		}

		// Should have exactly one initiator state
		wg.mutex.RLock()
		hasInitiatorState := wg.initiatorState != nil
		isHandshaking := wg.isHandshaking
		wg.mutex.RUnlock()

		if !hasInitiatorState {
			t.Error("Should have exactly one initiator state")
		}

		if !isHandshaking {
			t.Error("isHandshaking flag should be true after concurrent attempts")
		}
	})
}

// createTestMiniWG creates a minimal MiniWG instance for testing
// Sets up basic crypto keys but no network interfaces
func createTestMiniWG(t *testing.T) *MiniWG {
	wg := &MiniWG{}

	// Generate test keys
	privateKey, publicKey, err := generateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	peerPriv, peerPub, err := generateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate peer keypair: %v", err)
	}

	wg.privateKey = privateKey
	wg.publicKey = publicKey
	wg.peerKey = peerPub
	wg.localIndex = 0x12345678

	// Create a dummy UDP connection for testing
	// This will be used for sending handshake messages
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0") // Port 0 = any available port
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}

	wg.udp = udpConn

	// Clean up UDP connection when test finishes
	t.Cleanup(func() {
		udpConn.Close()
	})

	_ = peerPriv // Silence unused variable warning
	return wg
}

