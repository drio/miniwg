package device

import (
	"bytes"
	"testing"
)

// TestTrafficEncryptionDecryption tests packet encryption/decryption with proper key management
func TestTrafficEncryptionDecryption(t *testing.T) {
	var wg1, wg2 MiniWG

	var sendKey1 = [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	var recvKey1 = [32]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40}

	// WG1: send=sendKey1, recv=recvKey1
	// WG2: send=recvKey1, recv=sendKey1 (swapped, as in real handshake)
	wg1.establishSession(sendKey1, recvKey1, 2001)
	wg2.establishSession(recvKey1, sendKey1, 1001)

	wg1.localIndex = 1001
	wg2.localIndex = 2001

	testPacket := []byte("Hello from TUN interface! This is test tunnel traffic.")

	t.Run("Basic encryption and decryption", func(t *testing.T) {
		encryptedData, err := wg1.encryptPacket(testPacket)
		if err != nil {
			t.Fatalf("WG1 encryption failed: %v", err)
		}

		receiver, counter, payload, err := UnmarshalTransportData(encryptedData)
		if err != nil {
			t.Fatalf("failed to parse encrypted data: %v", err)
		}

		if receiver != wg1.peerIndex {
			t.Errorf("receiver index mismatch: expected %d, got %d", wg1.peerIndex, receiver)
		}

		if counter != 0 {
			t.Errorf("first packet counter should be 0, got %d", counter)
		}

		if len(payload) != len(testPacket)+16 { // +16 for auth tag
			t.Errorf("encrypted payload wrong size: expected %d, got %d", len(testPacket)+16, len(payload))
		}

		decryptedData, err := wg2.decryptPacket(encryptedData)
		if err != nil {
			t.Fatalf("WG2 decryption failed: %v", err)
		}

		if !bytes.Equal(decryptedData, testPacket) {
			t.Errorf("data integrity check failed: expected %s, got %s", testPacket, decryptedData)
		}
	})

	t.Run("Nonce counter increment", func(t *testing.T) {
		testPacket2 := []byte("Second packet")
		encryptedData2, err := wg1.encryptPacket(testPacket2)
		if err != nil {
			t.Fatalf("second encryption failed: %v", err)
		}

		_, counter2, _, _ := UnmarshalTransportData(encryptedData2)
		if counter2 != 1 {
			t.Errorf("nonce counter not incrementing correctly: expected 1, got %d", counter2)
		}

		decryptedData2, err := wg2.decryptPacket(encryptedData2)
		if err != nil {
			t.Fatalf("second decryption failed: %v", err)
		}

		if !bytes.Equal(decryptedData2, testPacket2) {
			t.Errorf("second packet integrity check failed")
		}
	})

	t.Run("Anti-replay protection", func(t *testing.T) {
		testPacket3 := []byte("Third packet")
		encryptedData3, err := wg1.encryptPacket(testPacket3)
		if err != nil {
			t.Fatalf("third encryption failed: %v", err)
		}

		_, err = wg2.decryptPacket(encryptedData3)
		if err != nil {
			t.Fatalf("third decryption failed: %v", err)
		}

		_, err = wg2.decryptPacket(encryptedData3) // Should be rejected
		if err == nil {
			t.Error("replay attack was not detected!")
		}
	})
}

// TestSessionManagement tests session establishment and reset
func TestSessionManagement(t *testing.T) {
	var wg MiniWG

	if wg.hasSession {
		t.Error("new MiniWG should not have active session")
	}

	testPacket := []byte("test")
	_, err := wg.encryptPacket(testPacket)
	if err == nil {
		t.Error("encryption should fail without active session")
	}

	sendKey := [32]byte{0x01}
	recvKey := [32]byte{0x02}
	wg.establishSession(sendKey, recvKey, 1001)

	if !wg.hasSession {
		t.Error("session should be active after establishment")
	}

	if wg.sendKey != sendKey {
		t.Error("send key not set correctly")
	}

	if wg.recvKey != recvKey {
		t.Error("receive key not set correctly")
	}

	if wg.peerIndex != 1001 {
		t.Error("peer index not set correctly")
	}

	wg.resetSession()

	if wg.hasSession {
		t.Error("session should be inactive after reset")
	}

	_, err = wg.encryptPacket(testPacket)
	if err == nil {
		t.Error("encryption should fail after session reset")
	}
}

// TestTransportMessageFormat tests transport data marshaling/unmarshaling
func TestTransportMessageFormat(t *testing.T) {
	receiver := uint32(12345)
	counter := uint64(67890)
	payload := []byte("test payload with auth tag")

	data := MarshalTransportData(receiver, counter, payload)

	if len(data) != 16+len(payload) {
		t.Errorf("transport data wrong size: expected %d, got %d", 16+len(payload), len(data))
	}

	if data[0] != MessageTypeTransportData {
		t.Errorf("wrong message type: expected %d, got %d", MessageTypeTransportData, data[0])
	}

	parsedReceiver, parsedCounter, parsedPayload, err := UnmarshalTransportData(data)
	if err != nil {
		t.Fatalf("failed to unmarshal transport data: %v", err)
	}

	if parsedReceiver != receiver {
		t.Errorf("receiver mismatch: expected %d, got %d", receiver, parsedReceiver)
	}

	if parsedCounter != counter {
		t.Errorf("counter mismatch: expected %d, got %d", counter, parsedCounter)
	}

	if !bytes.Equal(parsedPayload, payload) {
		t.Errorf("payload mismatch: expected %v, got %v", payload, parsedPayload)
	}
}

// TestInvalidTransportData tests error handling for malformed data
func TestInvalidTransportData(t *testing.T) {
	var wg MiniWG
	wg.establishSession([32]byte{}, [32]byte{}, 1001)
	wg.localIndex = 1001

	t.Run("Too short message", func(t *testing.T) {
		shortData := []byte{4, 0, 0, 0}
		_, err := wg.decryptPacket(shortData)
		if err == nil {
			t.Error("should reject too short transport data")
		}
	})

	t.Run("Wrong receiver index", func(t *testing.T) {
		wrongReceiver := MarshalTransportData(9999, 0, []byte("test"))
		_, err := wg.decryptPacket(wrongReceiver)
		if err == nil {
			t.Error("should reject wrong receiver index")
		}
	})

	t.Run("Invalid counter (replay)", func(t *testing.T) {
		wg.recvCounter = 5

		replayData := MarshalTransportData(1001, 3, []byte("test")) // Counter 3 < 5, should be rejected
		_, err := wg.decryptPacket(replayData)
		if err == nil {
			t.Error("should reject replayed counter")
		}
	})
}
