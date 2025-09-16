package main

import (
	"crypto/rand"
	"testing"
)

// generateRandomIndex creates a random 32-bit sender/receiver index for WireGuard messages
func generateRandomIndex(t *testing.T) uint32 {
	var indexBytes [4]byte
	if _, err := rand.Read(indexBytes[:]); err != nil {
		t.Fatalf("failed to generate random index: %v", err)
	}
	// Convert to little-endian uint32
	//   If the random bytes are [0x12, 0x34, 0x56, 0x78]:
	// index = 0x12 | (0x34<<8) | (0x56<<16) | (0x78<<24)
	//       = 0x12 | 0x3400 | 0x560000 | 0x78000000
	//       = 0x78563412
	return uint32(indexBytes[0]) |
		uint32(indexBytes[1])<<8 |
		uint32(indexBytes[2])<<16 |
		uint32(indexBytes[3])<<24
}

// TestHandshakeInitiation tests the creation of handshake initiation messages
func TestHandshakeInitiation(t *testing.T) {
	// Generate keys for testing
	ourPrivKey, ourPubKey, err := generateKeypair()
	if err != nil {
		t.Fatalf("failed to generate our keypair: %v", err)
	}

	_, peerPubKey, err := generateKeypair()
	if err != nil {
		t.Fatalf("failed to generate peer keypair: %v", err)
	}

	// Generate random sender index
	senderIndex := generateRandomIndex(t)

	// Create the handshake initiation
	msg, state, err := createHandshakeInitiation(ourPrivKey, ourPubKey, peerPubKey, senderIndex)
	if err != nil {
		t.Fatalf("handshake initiation failed: %v", err)
	}

	// Verify message structure
	if msg.Type != MessageTypeHandshakeInitiation {
		t.Errorf("wrong message type: expected %d, got %d", MessageTypeHandshakeInitiation, msg.Type)
	}

	if msg.Sender != senderIndex {
		t.Errorf("wrong sender index: expected %d, got %d", senderIndex, msg.Sender)
	}

	// Marshal the message to bytes
	msgBytes := msg.Marshal()
	if len(msgBytes) != 148 {
		t.Errorf("wrong message size: expected 148, got %d", len(msgBytes))
	}

	// Verify state is populated
	if state.chainingKey == [32]byte{} {
		t.Error("chaining key should not be empty")
	}

	if state.hash == [32]byte{} {
		t.Error("hash should not be empty")
	}
}

// TestFullHandshake tests the complete 4-part handshake process
func TestFullHandshake(t *testing.T) {
	// Generate keys for both parties
	initiatorPrivKey, initiatorPubKey, err := generateKeypair()
	if err != nil {
		t.Fatalf("failed to generate initiator keypair: %v", err)
	}

	responderPrivKey, responderPubKey, err := generateKeypair()
	if err != nil {
		t.Fatalf("failed to generate responder keypair: %v", err)
	}

	// Generate sender indexes
	senderIndex := generateRandomIndex(t)
	responderIndex := generateRandomIndex(t)

	t.Run("Part 1: Create handshake initiation", func(t *testing.T) {
		// Create handshake initiation as initiator
		msg, initiatorState, err := createHandshakeInitiation(initiatorPrivKey, initiatorPubKey, responderPubKey, senderIndex)
		if err != nil {
			t.Fatalf("handshake initiation creation failed: %v", err)
		}

		// Store for next test
		t.Cleanup(func() {
			// Store initiatorState for use in other tests
		})

		// Marshal the message
		msgBytes := msg.Marshal()
		if len(msgBytes) != 148 {
			t.Errorf("wrong initiation message size: expected 148, got %d", len(msgBytes))
		}

		t.Run("Part 2: Process handshake initiation", func(t *testing.T) {
			// Process handshake initiation as responder
			var zeroTimestamp [12]byte // For first handshake, no previous timestamp
			responderState, err := processHandshakeInitiation(msgBytes, responderPrivKey, responderPubKey, zeroTimestamp)
			if err != nil {
				t.Fatalf("handshake initiation processing failed: %v", err)
			}

			// Verify states are synchronized
			if initiatorState.chainingKey != responderState.chainingKey {
				t.Error("chaining keys don't match after initiation processing")
			}

			if initiatorState.hash != responderState.hash {
				t.Error("hashes don't match after initiation processing")
			}

			// Verify responder correctly identified initiator
			if responderState.initiatorStaticPublic != initiatorPubKey {
				t.Error("responder failed to identify initiator correctly")
			}

			t.Run("Part 3: Create handshake response", func(t *testing.T) {
				// Create handshake response as responder
				responseMsg, finalResponderState, err := createHandshakeResponse(responderState, responderIndex)
				if err != nil {
					t.Fatalf("handshake response creation failed: %v", err)
				}

				// Verify response message structure
				if responseMsg.Type != MessageTypeHandshakeResponse {
					t.Errorf("wrong response type: expected %d, got %d", MessageTypeHandshakeResponse, responseMsg.Type)
				}

				if responseMsg.Sender != responderIndex {
					t.Errorf("wrong response sender: expected %d, got %d", responderIndex, responseMsg.Sender)
				}

				if responseMsg.Receiver != senderIndex {
					t.Errorf("wrong response receiver: expected %d, got %d", senderIndex, responseMsg.Receiver)
				}

				// Marshal the response message
				responseMsgBytes := responseMsg.Marshal()
				if len(responseMsgBytes) != 92 {
					t.Errorf("wrong response message size: expected 92, got %d", len(responseMsgBytes))
				}

				t.Run("Part 4: Process handshake response", func(t *testing.T) {
					// Process handshake response as initiator
					finalInitiatorState, err := processHandshakeResponse(responseMsgBytes, initiatorState)
					if err != nil {
						t.Fatalf("handshake response processing failed: %v", err)
					}

					// Verify both sides have the same final chaining key
					if finalInitiatorState.chainingKey != finalResponderState.chainingKey {
						t.Error("final chaining keys don't match")
					}

					if finalInitiatorState.hash != finalResponderState.hash {
						t.Error("final hashes don't match")
					}

					t.Run("Transport key derivation", func(t *testing.T) {
						// Derive transport keys - initiator and responder have swapped key assignments
						initKey1, initKey2, err := deriveTransportKeys(finalInitiatorState.chainingKey)
						if err != nil {
							t.Fatalf("initiator transport key derivation failed: %v", err)
						}
						// For initiator: first key is sending, second is receiving
						initSendKey := initKey1
						initRecvKey := initKey2

						respKey1, respKey2, err := deriveTransportKeys(finalResponderState.chainingKey)
						if err != nil {
							t.Fatalf("responder transport key derivation failed: %v", err)
						}
						// For responder: first key is receiving, second is sending (swapped from initiator)
						respRecvKey := respKey1
						respSendKey := respKey2

						// Verify key relationship: initiator send = responder receive, etc.
						if initSendKey != respRecvKey {
							t.Error("initiator send key doesn't match responder receive key")
						}

						if initRecvKey != respSendKey {
							t.Error("initiator receive key doesn't match responder send key")
						}

						t.Logf("✅ Complete handshake success!")
						t.Logf("✅ All 4 parts completed successfully")
						t.Logf("✅ Transport keys derived and verified")
					})
				})
			})
		})
	})
}

// TestHandshakeMACs tests MAC1 and MAC2 calculation
func TestHandshakeMACs(t *testing.T) {
	// Generate test keys
	_, ourPubKey, err := generateKeypair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	// Test message bytes
	testMessage := []byte("test message for MAC calculation")

	t.Run("MAC1 calculation", func(t *testing.T) {
		mac1, err := calculateMAC1(testMessage, ourPubKey)
		if err != nil {
			t.Fatalf("MAC1 calculation failed: %v", err)
		}

		// MAC1 should be 16 bytes
		if len(mac1) != 16 {
			t.Errorf("MAC1 wrong length: expected 16, got %d", len(mac1))
		}

		// Same inputs should produce same MAC1
		mac1Again, err := calculateMAC1(testMessage, ourPubKey)
		if err != nil {
			t.Fatalf("MAC1 calculation failed on repeat: %v", err)
		}

		if mac1 != mac1Again {
			t.Error("MAC1 calculation not deterministic")
		}
	})

	t.Run("MAC2 calculation", func(t *testing.T) {
		// Test with no cookie (should be zeros)
		mac2 := calculateMAC2(testMessage, nil)
		var zeroMAC [16]byte
		if mac2 != zeroMAC {
			t.Error("MAC2 should be zeros when no cookie provided")
		}

		// Test with cookie
		cookie := []byte("test cookie data")
		mac2WithCookie := calculateMAC2(testMessage, cookie)
		if mac2WithCookie == zeroMAC {
			t.Error("MAC2 should not be zeros when cookie provided")
		}
	})
}

// TestHandshakeValidation tests various validation scenarios
func TestHandshakeValidation(t *testing.T) {
	// Generate keys
	ourPrivKey, ourPubKey, err := generateKeypair()
	if err != nil {
		t.Fatalf("failed to generate our keypair: %v", err)
	}

	_, peerPubKey, err := generateKeypair()
	if err != nil {
		t.Fatalf("failed to generate peer keypair: %v", err)
	}

	// Create valid handshake initiation
	msg, _, err := createHandshakeInitiation(ourPrivKey, ourPubKey, peerPubKey, 12345)
	if err != nil {
		t.Fatalf("failed to create handshake initiation: %v", err)
	}

	msgBytes := msg.Marshal()

	t.Run("Invalid message length", func(t *testing.T) {
		shortMsg := msgBytes[:100] // Too short
		var zeroTimestamp [12]byte
		_, err := processHandshakeInitiation(shortMsg, ourPrivKey, ourPubKey, zeroTimestamp)
		if err == nil {
			t.Error("should reject message with invalid length")
		}
	})

	t.Run("Invalid message type", func(t *testing.T) {
		invalidMsg := make([]byte, len(msgBytes))
		copy(invalidMsg, msgBytes)
		invalidMsg[0] = 99 // Wrong message type

		var msg HandshakeInitiation
		err := msg.Unmarshal(invalidMsg)
		if err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		var zeroTimestamp [12]byte
		_, err = processHandshakeInitiation(invalidMsg, ourPrivKey, ourPubKey, zeroTimestamp)
		if err == nil {
			t.Error("should reject message with invalid type")
		}
	})

	t.Run("MAC1 validation", func(t *testing.T) {
		invalidMsg := make([]byte, len(msgBytes))
		copy(invalidMsg, msgBytes)

		// Corrupt MAC1
		for i := 116; i < 132; i++ {
			invalidMsg[i] ^= 0xFF
		}

		var zeroTimestamp [12]byte
		_, err := processHandshakeInitiation(invalidMsg, ourPrivKey, ourPubKey, zeroTimestamp)
		if err == nil {
			t.Error("should reject message with invalid MAC1")
		}
	})
}

