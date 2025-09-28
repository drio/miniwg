// transport.go
//
// WireGuard traffic encryption and decryption routines
//
// After a successful handshake, both peers have derived:
// - sendKey: for encrypting outgoing traffic
// - recvKey: for decrypting incoming traffic
// - Nonce counters: to prevent replay attacks
//
// Traffic format:
// [Type:1][Reserved:3][Receiver:4][Counter:8][EncryptedPayload + AuthTag:variable]

package device

import (
	"fmt"
	"sync"
)

// encryptPacket encrypts a plaintext packet for transmission over the tunnel
// Uses ChaCha20-Poly1305 AEAD with the sending key and incrementing nonce counter
func (wg *MiniWG) encryptPacket(plaintext []byte) ([]byte, error) {
	if !wg.hasSession {
		return nil, fmt.Errorf("no active session - handshake required")
	}

	// No associated data - authentication covers only the encrypted payload
	ciphertext, err := chachaPolyEncrypt(wg.sendKey, wg.sendNonce, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %v", err)
	}

	transportMsg := MarshalTransportData(wg.peerIndex, wg.sendNonce, ciphertext)

	// Increment nonce counter after successful encryption
	wg.sendNonce++

	return transportMsg, nil
}

// decryptPacket decrypts an incoming transport packet
// Validates nonce counter to prevent replay attacks
func (wg *MiniWG) decryptPacket(transportData []byte) ([]byte, error) {
	if !wg.hasSession {
		return nil, fmt.Errorf("no active session - handshake required")
	}

	// Parse transport message header
	receiver, counter, encryptedPayload, err := UnmarshalTransportData(transportData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse transport data: %v", err)
	}

	// Verify receiver index matches our session
	if receiver != wg.localIndex {
		return nil, fmt.Errorf("receiver index mismatch: expected %d, got %d", wg.localIndex, receiver)
	}

	// Anti-replay: counter must be greater than last received
	// For first packet, allow counter >= recvCounter (both start at 0)
	if counter < wg.recvCounter || (wg.recvCounter > 0 && counter == wg.recvCounter) {
		return nil, fmt.Errorf("replay attack detected: counter %d <= last %d", counter, wg.recvCounter)
	}

	// Decrypt with ChaCha20-Poly1305 using receive key and message counter
	plaintext, err := chachaPolyDecrypt(wg.recvKey, counter, encryptedPayload, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	wg.recvCounter = counter

	return plaintext, nil
}

// Session management helpers

var sessionMutex sync.RWMutex

// establishSession sets up transport keys after successful handshake
// Called after handshake completion with derived keys
func (wg *MiniWG) establishSession(sendKey, recvKey [32]byte, peerIndex uint32) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	wg.sendKey = sendKey
	wg.recvKey = recvKey
	wg.peerIndex = peerIndex
	wg.sendNonce = 0
	wg.recvCounter = 0
	wg.hasSession = true

	// Start the rekey timer for this session (if available)
	if wg.rekeyTimer != nil {
		wg.rekeyTimer.Reset(REKEY_AFTER_TIME)
	}
}

// resetSession clears session state (called on rekey or errors)
func (wg *MiniWG) resetSession() {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	wg.hasSession = false
	wg.sendKey = [32]byte{}
	wg.recvKey = [32]byte{}
	wg.sendNonce = 0
	wg.recvCounter = 0
	wg.peerIndex = 0

	// Stop the rekey timer when session is reset (if available)
	if wg.rekeyTimer != nil {
		wg.rekeyTimer.Stop()
	}
}

// Traffic handling helpers

// handleTunnelTraffic processes outgoing traffic from TUN interface
// Encrypts packets and sends them over UDP to peer
func (wg *MiniWG) handleTunnelTraffic(packet []byte) error {
	// Encrypt the packet
	encryptedPacket, err := wg.encryptPacket(packet)
	if err != nil {
		return fmt.Errorf("failed to encrypt packet: %v", err)
	}

	// Send over UDP to peer
	_, err = wg.udp.WriteToUDP(encryptedPacket, wg.peerAddr)
	if err != nil {
		return fmt.Errorf("failed to send encrypted packet: %v", err)
	}

	return nil
}

// handleTransportData processes incoming encrypted traffic from UDP
// Decrypts packets and injects them into TUN interface
func (wg *MiniWG) handleTransportData(transportData []byte) error {
	// Decrypt the packet
	plaintext, err := wg.decryptPacket(transportData)
	if err != nil {
		return fmt.Errorf("failed to decrypt packet: %v", err)
	}

	// Inject into TUN interface
	_, err = wg.tun.Write(plaintext)
	if err != nil {
		return fmt.Errorf("failed to write to TUN interface: %v", err)
	}

	return nil
}
