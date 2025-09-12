// handshake.go
//
// Noise_IK handshake implementation for WireGuard
//
// Contains:
// - Handshake initiation message creation and processing
// - Handshake response message creation and processing
// - Noise_IK state machine implementation
// - Chaining key and hash computations
// - Static and ephemeral key mixing
// - Transport key derivation after successful handshake

package main

import (
	"fmt"
)

// HandshakeInitiationState holds intermediate values during handshake creation
// This helps us see exactly what's happening at each step
type HandshakeInitiationState struct {
	// Noise_IK state variables
	chainingKey [32]byte // Ci in the spec
	hash        [32]byte // Hi in the spec

	// Ephemeral keys for this handshake
	ephemeralPrivate [32]byte
	ephemeralPublic  [32]byte

	// Static keys (peer and our own)
	ourStaticPrivate [32]byte
	ourStaticPublic  [32]byte
	peerStaticPublic [32]byte

	// Generated message fields
	senderIndex        uint32
	encryptedStatic    [48]byte // 32 bytes + 16 byte auth tag
	encryptedTimestamp [28]byte // 12 bytes + 16 byte auth tag

	// Intermediate values for debugging
	tempKey1 [32]byte
	tempKey2 [32]byte
}

// createHandshakeInitiation (Part 1/4) creates the first message of the Noise_IK handshake
// Following the exact steps from WireGuard protocol specification
func createHandshakeInitiation(ourStaticPriv, ourStaticPub, peerStaticPub [32]byte, senderIndex uint32) (*HandshakeInitiation, *HandshakeInitiationState, error) {

	state := &HandshakeInitiationState{
		ourStaticPrivate: ourStaticPriv,
		ourStaticPublic:  ourStaticPub,
		peerStaticPublic: peerStaticPub,
		senderIndex:      senderIndex,
	}

	// Step 1: Initialize chaining key
	// initiator.chaining_key = HASH(CONSTRUCTION)
	fmt.Println("=== STEP 1: Initialize chaining key ===")
	construction := []byte(CONSTRUCTION) // "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	state.chainingKey = blake2sHash(construction)
	fmt.Printf("CONSTRUCTION: %s\n", CONSTRUCTION)
	fmt.Printf("chaining_key = HASH(CONSTRUCTION): %x\n", state.chainingKey)

	// Step 2: Initialize hash
	// initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
	fmt.Println("\n=== STEP 2: Initialize hash ===")
	identifier := []byte(IDENTIFIER) // "WireGuard v1 zx2c4 Jason@zx2c4.com"

	// First: HASH(chaining_key || IDENTIFIER)
	temp := append(state.chainingKey[:], identifier...)
	tempHash := blake2sHash(temp)
	fmt.Printf("IDENTIFIER: %s\n", IDENTIFIER)
	fmt.Printf("temp_hash = HASH(chaining_key || IDENTIFIER): %x\n", tempHash)

	// Second: HASH(temp_hash || responder.static_public)
	temp2 := append(tempHash[:], peerStaticPub[:]...)
	state.hash = blake2sHash(temp2)
	fmt.Printf("peer_static_public: %x\n", peerStaticPub)
	fmt.Printf("hash = HASH(temp_hash || peer_static_public): %x\n", state.hash)

	// Step 3: Generate ephemeral keypair
	// initiator.ephemeral_private = DH_GENERATE()
	fmt.Println("\n=== STEP 3: Generate ephemeral keypair ===")
	ephemeralPriv, ephemeralPub, err := generateKeypair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral keypair: %v", err)
	}
	state.ephemeralPrivate = ephemeralPriv
	state.ephemeralPublic = ephemeralPub
	fmt.Printf("ephemeral_private: %x\n", state.ephemeralPrivate)
	fmt.Printf("ephemeral_public: %x\n", state.ephemeralPublic)

	// Step 4: Mix ephemeral public key into hash
	// initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
	fmt.Println("\n=== STEP 4: Mix ephemeral public key into hash ===")
	temp3 := append(state.hash[:], state.ephemeralPublic[:]...)
	state.hash = blake2sHash(temp3)
	fmt.Printf("hash = HASH(old_hash || ephemeral_public): %x\n", state.hash)

	// Step 5: Mix ephemeral public key into chaining key using KDF1
	// temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
	// initiator.chaining_key = HMAC(temp, 0x1)
	fmt.Println("\n=== STEP 5: Mix ephemeral public key into chaining key (KDF1) ===")
	newChainingKey, err := kdf1(state.chainingKey[:], state.ephemeralPublic[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf1 failed: %v", err)
	}
	state.chainingKey = newChainingKey
	fmt.Printf("chaining_key = KDF1(old_chaining_key, ephemeral_public): %x\n", state.chainingKey)

	// Step 6: Perform DH with ephemeral private and peer static public
	// Then derive encryption key for static key encryption
	fmt.Println("\n=== STEP 6: DH(ephemeral_private, peer_static_public) + KDF2 ===")
	dhResult1, err := dhOperation(state.ephemeralPrivate, state.peerStaticPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("DH operation 1 failed: %v", err)
	}
	fmt.Printf("dh1 = DH(ephemeral_private, peer_static_public): %x\n", dhResult1)

	// temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
	// initiator.chaining_key = HMAC(temp, 0x1)
	// key = HMAC(temp, initiator.chaining_key || 0x2)
	newChainingKey2, encryptKey1, err := kdf2(state.chainingKey[:], dhResult1[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf2 failed: %v", err)
	}
	state.chainingKey = newChainingKey2
	state.tempKey1 = encryptKey1
	fmt.Printf("chaining_key = KDF2.key1(chaining_key, dh1): %x\n", state.chainingKey)
	fmt.Printf("encrypt_key1 = KDF2.key2(chaining_key, dh1): %x\n", state.tempKey1)

	// Step 7: Encrypt static public key
	// msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
	fmt.Println("\n=== STEP 7: Encrypt static public key ===")
	encryptedStatic, err := chachaPolyEncrypt(state.tempKey1, 0, state.ourStaticPublic[:], state.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt static key: %v", err)
	}
	if len(encryptedStatic) != 48 { // 32 bytes + 16 byte auth tag
		return nil, nil, fmt.Errorf("encrypted static key wrong length: got %d, expected 48", len(encryptedStatic))
	}
	copy(state.encryptedStatic[:], encryptedStatic)
	fmt.Printf("our_static_public: %x\n", state.ourStaticPublic)
	fmt.Printf("encrypted_static: %x\n", state.encryptedStatic)

	// Step 8: Mix encrypted static into hash
	// initiator.hash = HASH(initiator.hash || msg.encrypted_static)
	fmt.Println("\n=== STEP 8: Mix encrypted static into hash ===")
	temp4 := append(state.hash[:], state.encryptedStatic[:]...)
	state.hash = blake2sHash(temp4)
	fmt.Printf("hash = HASH(old_hash || encrypted_static): %x\n", state.hash)

	// Step 9: Perform DH with our static private and peer static public
	// Then derive encryption key for timestamp encryption
	fmt.Println("\n=== STEP 9: DH(our_static_private, peer_static_public) + KDF2 ===")
	dhResult2, err := dhOperation(state.ourStaticPrivate, state.peerStaticPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("DH operation 2 failed: %v", err)
	}
	fmt.Printf("dh2 = DH(our_static_private, peer_static_public): %x\n", dhResult2)

	// temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
	// initiator.chaining_key = HMAC(temp, 0x1)
	// key = HMAC(temp, initiator.chaining_key || 0x2)
	newChainingKey3, encryptKey2, err := kdf2(state.chainingKey[:], dhResult2[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf2 failed: %v", err)
	}
	state.chainingKey = newChainingKey3
	state.tempKey2 = encryptKey2
	fmt.Printf("chaining_key = KDF2.key1(chaining_key, dh2): %x\n", state.chainingKey)
	fmt.Printf("encrypt_key2 = KDF2.key2(chaining_key, dh2): %x\n", state.tempKey2)

	// Step 10: Encrypt timestamp
	// msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
	fmt.Println("\n=== STEP 10: Encrypt timestamp ===")
	timestamp := generateTimestamp()
	fmt.Printf("timestamp: %x\n", timestamp)
	encryptedTimestamp, err := chachaPolyEncrypt(state.tempKey2, 0, timestamp[:], state.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt timestamp: %v", err)
	}
	if len(encryptedTimestamp) != 28 { // 12 bytes + 16 byte auth tag
		return nil, nil, fmt.Errorf("encrypted timestamp wrong length: got %d, expected 28", len(encryptedTimestamp))
	}
	copy(state.encryptedTimestamp[:], encryptedTimestamp)
	fmt.Printf("encrypted_timestamp: %x\n", state.encryptedTimestamp)

	// Step 11: Final hash update
	// initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
	fmt.Println("\n=== STEP 11: Final hash update ===")
	temp5 := append(state.hash[:], state.encryptedTimestamp[:]...)
	state.hash = blake2sHash(temp5)
	fmt.Printf("final_hash = HASH(old_hash || encrypted_timestamp): %x\n", state.hash)

	// Step 12: Create the message structure with MAC calculations
	fmt.Println("\n=== STEP 12: Create HandshakeInitiation message ===")
	msg := &HandshakeInitiation{
		Type:      MessageTypeHandshakeInitiation,
		Sender:    state.senderIndex,
		Ephemeral: state.ephemeralPublic,
		Static:    state.encryptedStatic,
		Timestamp: state.encryptedTimestamp,
		// MAC1 and MAC2 will be calculated below
	}

	fmt.Printf("Message type: %d\n", msg.Type)
	fmt.Printf("Sender index: %d\n", msg.Sender)
	fmt.Printf("Ephemeral: %x\n", msg.Ephemeral)
	fmt.Printf("Static: %x\n", msg.Static)
	fmt.Printf("Timestamp: %x\n", msg.Timestamp)

	// Step 13: Calculate MAC1 and MAC2
	fmt.Println("\n=== STEP 13: Calculate MAC1 and MAC2 ===")

	// Marshal message without MACs to get bytes for MAC calculation
	msgBytes := msg.Marshal()
	msgBytesForMAC1 := msgBytes[:len(msgBytes)-32] // Exclude MAC1(16) + MAC2(16) = 32 bytes

	// Calculate MAC1
	mac1, err := calculateMAC1(msgBytesForMAC1, state.peerStaticPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate MAC1: %v", err)
	}
	msg.MAC1 = mac1
	fmt.Printf("MAC1: %x\n", msg.MAC1)

	// Calculate MAC2 (no cookie for now, so will be zeros)
	msgBytes = msg.Marshal()
	msgBytesForMAC2 := msgBytes[:len(msgBytes)-16] // Exclude MAC2(16) bytes
	mac2 := calculateMAC2(msgBytesForMAC2, nil)    // No cookie
	msg.MAC2 = mac2
	fmt.Printf("MAC2: %x\n", msg.MAC2)

	fmt.Printf("\n=== HANDSHAKE INITIATION COMPLETE ===\n")
	fmt.Printf("Final chaining_key: %x\n", state.chainingKey)
	fmt.Printf("Final hash: %x\n", state.hash)

	return msg, state, nil
}


// calculateMAC1 computes MAC1 for handshake messages
// MAC1 = MAC(HASH(LABEL_MAC1 || peer_static_public), message_bytes)
//
// MAC1 Purpose and Security Properties:
// - Authentication: Proves sender knows the responder's static public key
// - DoS Protection: Prevents random/invalid packets from consuming CPU cycles
// - Silence Property: Allows responder to remain silent to unauthorized senders
// - Access Control: Only peers who know the public key can elicit any response
// - Anti-Scanning: Makes WireGuard invisible to network scanners and port probes
// - Always Required: Must be present and valid on ALL handshake messages
//
// Security Note: While the static public key isn't secret, knowing it proves
// the sender already knows about this WireGuard endpoint, providing sufficient
// proof of legitimacy within the threat model of staying stealthy.
func calculateMAC1(messageBytes []byte, peerStaticPublic [32]byte) ([16]byte, error) {
	var result [16]byte

	// Create MAC key: HASH(LABEL_MAC1 || peer_static_public)
	labelMac1 := []byte(LABEL_MAC1) // "mac1----"
	keyInput := append(labelMac1, peerStaticPublic[:]...)
	macKey := blake2sHash(keyInput)

	// Calculate MAC1: MAC(mac_key, message_bytes)
	mac1, err := blake2sMac(macKey[:], messageBytes)
	if err != nil {
		return result, fmt.Errorf("failed to calculate MAC1: %v", err)
	}

	return mac1, nil
}

// calculateMAC2 computes MAC2 for handshake messages
// MAC2 = MAC(cookie, message_bytes) OR zeros if no cookie
//
// MAC2 Purpose and Cookie System:
// - DoS Mitigation: Used when responder is under heavy load
// - Rate Limiting: Ties handshake messages to specific IP addresses
// - Proof of IP Ownership: Cookie is MAC of sender's IP using responder's secret
// - Load Shedding: Responder can reject messages without valid MAC2 when overloaded
// - Normally Empty: Set to zeros unless sender has received a cookie reply
//
// Cookie Flow:
// 1. Normal: MAC1=valid, MAC2=zeros → message processed
// 2. Under load: MAC1=valid, MAC2=zeros → send cookie reply (don't process)
// 3. With cookie: MAC1=valid, MAC2=valid → message processed even under load
//
// This enables 1-RTT handshake in normal conditions while providing DoS protection
// when needed, without breaking the protocol's stateless appearance.
func calculateMAC2(messageBytes []byte, cookie []byte) [16]byte {
	var result [16]byte

	// If no cookie available, MAC2 is all zeros
	if len(cookie) == 0 {
		return result // Already zero-initialized
	}

	// Calculate MAC2: MAC(cookie, message_bytes)
	mac2, err := blake2sMac(cookie, messageBytes)
	if err != nil {
		// If MAC calculation fails, return zeros (effectively no cookie)
		return result
	}

	return mac2
}

// HandshakeResponderState holds responder's state during handshake processing
// This mirrors the initiator state but from the responder's perspective
type HandshakeResponderState struct {
	// Noise_IK state variables (same as initiator after sync)
	chainingKey [32]byte // Cr in the spec - should match initiator's Ci
	hash        [32]byte // Hr in the spec - should match initiator's Hi

	// Received initiator data
	initiatorEphemeralPublic [32]byte
	initiatorStaticPublic    [32]byte // Decrypted from message
	initiatorSenderIndex     uint32
	receivedTimestamp        [12]byte // Decrypted TAI64N timestamp

	// Our responder keys
	ourStaticPrivate [32]byte
	ourStaticPublic  [32]byte

	// Validation results
	mac1Valid      bool
	mac2Valid      bool
	timestampValid bool
}

// processHandshakeInitiation (Part 2/4) processes the first handshake message (responder side)
// This implements the reverse of createHandshakeInitiation - it takes the received
// message bytes and performs all the same cryptographic operations to sync state
func processHandshakeInitiation(messageBytes []byte, ourStaticPriv, ourStaticPub [32]byte, lastTimestamp [12]byte) (*HandshakeResponderState, error) {

	fmt.Println("🔓 Processing WireGuard Handshake Initiation (Responder Side)")

	state := &HandshakeResponderState{
		ourStaticPrivate: ourStaticPriv,
		ourStaticPublic:  ourStaticPub,
	}

	// Step 1: Unmarshal the received message
	fmt.Println("\n=== STEP 1: Unmarshal received message ===")
	var msg HandshakeInitiation
	if err := msg.Unmarshal(messageBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal handshake initiation: %v", err)
	}

	if msg.Type != MessageTypeHandshakeInitiation {
		return nil, fmt.Errorf("invalid message type: expected %d, got %d", MessageTypeHandshakeInitiation, msg.Type)
	}

	state.initiatorSenderIndex = msg.Sender
	state.initiatorEphemeralPublic = msg.Ephemeral

	fmt.Printf("Message type: %d\n", msg.Type)
	fmt.Printf("Sender index: %d\n", state.initiatorSenderIndex)
	fmt.Printf("Ephemeral public: %x\n", state.initiatorEphemeralPublic)
	fmt.Printf("Encrypted static: %x\n", msg.Static)
	fmt.Printf("Encrypted timestamp: %x\n", msg.Timestamp)

	// Step 2: Validate MAC1 - proves sender knows our static public key
	fmt.Println("\n=== STEP 2: Validate MAC1 ===")
	msgBytesForMAC1 := messageBytes[:len(messageBytes)-32] // Exclude MAC1(16) + MAC2(16)
	expectedMAC1, err := calculateMAC1(msgBytesForMAC1, state.ourStaticPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate expected MAC1: %v", err)
	}

	state.mac1Valid = (msg.MAC1 == expectedMAC1)
	fmt.Printf("Expected MAC1: %x\n", expectedMAC1)
	fmt.Printf("Received MAC1:  %x\n", msg.MAC1)
	fmt.Printf("MAC1 valid: %v\n", state.mac1Valid)

	if !state.mac1Valid {
		return nil, fmt.Errorf("invalid MAC1 - sender doesn't know our static public key")
	}

	// Step 3: Validate MAC2 (currently just check if zeros)
	fmt.Println("\n=== STEP 3: Validate MAC2 ===")
	var zeroMAC2 [16]byte
	state.mac2Valid = (msg.MAC2 == zeroMAC2)
	fmt.Printf("MAC2: %x\n", msg.MAC2)
	fmt.Printf("MAC2 valid (should be zeros): %v\n", state.mac2Valid)

	if !state.mac2Valid {
		// In a real implementation, this would trigger cookie reply under load
		fmt.Println("NOTE: MAC2 not zeros - would need cookie validation under load")
	}

	// Step 4: Sync cryptographic ledger - perform same operations as initiator
	fmt.Println("\n=== STEP 4: Initialize chaining key (sync with initiator) ===")
	// responder.chaining_key = HASH(CONSTRUCTION)
	construction := []byte(CONSTRUCTION)
	state.chainingKey = blake2sHash(construction)
	fmt.Printf("chaining_key = HASH(CONSTRUCTION): %x\n", state.chainingKey)

	// Step 5: Initialize hash (sync with initiator)
	fmt.Println("\n=== STEP 5: Initialize hash (sync with initiator) ===")
	// responder.hash = HASH(HASH(responder.chaining_key || IDENTIFIER) || responder.static_public)
	identifier := []byte(IDENTIFIER)
	temp := append(state.chainingKey[:], identifier...)
	tempHash := blake2sHash(temp)
	temp2 := append(tempHash[:], state.ourStaticPublic[:]...)
	state.hash = blake2sHash(temp2)
	fmt.Printf("hash = HASH(HASH(chaining_key || IDENTIFIER) || our_static_public): %x\n", state.hash)

	// Step 6: Mix received ephemeral public key into hash (sync with initiator)
	fmt.Println("\n=== STEP 6: Mix ephemeral public key into hash ===")
	// responder.hash = HASH(responder.hash || received_ephemeral_public)
	temp3 := append(state.hash[:], state.initiatorEphemeralPublic[:]...)
	state.hash = blake2sHash(temp3)
	fmt.Printf("hash = HASH(old_hash || received_ephemeral_public): %x\n", state.hash)

	// Step 7: Mix ephemeral public key into chaining key using KDF1 (sync with initiator)
	fmt.Println("\n=== STEP 7: Mix ephemeral public key into chaining key (KDF1) ===")
	newChainingKey, err := kdf1(state.chainingKey[:], state.initiatorEphemeralPublic[:])
	if err != nil {
		return nil, fmt.Errorf("kdf1 failed: %v", err)
	}
	state.chainingKey = newChainingKey
	fmt.Printf("chaining_key = KDF1(old_chaining_key, received_ephemeral_public): %x\n", state.chainingKey)

	// Step 8: Perform DH and derive key for static decryption
	fmt.Println("\n=== STEP 8: DH(our_static_private, received_ephemeral_public) + KDF2 ===")
	dhResult1, err := dhOperation(state.ourStaticPrivate, state.initiatorEphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("DH operation 1 failed: %v", err)
	}
	fmt.Printf("dh1 = DH(our_static_private, received_ephemeral_public): %x\n", dhResult1)

	newChainingKey2, decryptKey1, err := kdf2(state.chainingKey[:], dhResult1[:])
	if err != nil {
		return nil, fmt.Errorf("kdf2 failed: %v", err)
	}
	state.chainingKey = newChainingKey2
	fmt.Printf("chaining_key = KDF2.key1(chaining_key, dh1): %x\n", state.chainingKey)
	fmt.Printf("decrypt_key1 = KDF2.key2(chaining_key, dh1): %x\n", decryptKey1)

	// Step 9: Decrypt and verify initiator's static public key
	fmt.Println("\n=== STEP 9: Decrypt initiator's static public key ===")
	decryptedStatic, err := chachaPolyDecrypt(decryptKey1, 0, msg.Static[:], state.hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt static key: %v", err)
	}
	if len(decryptedStatic) != 32 {
		return nil, fmt.Errorf("decrypted static key wrong length: got %d, expected 32", len(decryptedStatic))
	}
	copy(state.initiatorStaticPublic[:], decryptedStatic)
	fmt.Printf("decrypted_static_public: %x\n", state.initiatorStaticPublic)

	// Step 10: Mix encrypted static into hash (sync with initiator)
	fmt.Println("\n=== STEP 10: Mix encrypted static into hash ===")
	temp4 := append(state.hash[:], msg.Static[:]...)
	state.hash = blake2sHash(temp4)
	fmt.Printf("hash = HASH(old_hash || encrypted_static): %x\n", state.hash)

	// Step 11: Perform DH and derive key for timestamp decryption
	fmt.Println("\n=== STEP 11: DH(our_static_private, initiator_static_public) + KDF2 ===")
	dhResult2, err := dhOperation(state.ourStaticPrivate, state.initiatorStaticPublic)
	if err != nil {
		return nil, fmt.Errorf("DH operation 2 failed: %v", err)
	}
	fmt.Printf("dh2 = DH(our_static_private, initiator_static_public): %x\n", dhResult2)

	newChainingKey3, decryptKey2, err := kdf2(state.chainingKey[:], dhResult2[:])
	if err != nil {
		return nil, fmt.Errorf("kdf2 failed: %v", err)
	}
	state.chainingKey = newChainingKey3
	fmt.Printf("chaining_key = KDF2.key1(chaining_key, dh2): %x\n", state.chainingKey)
	fmt.Printf("decrypt_key2 = KDF2.key2(chaining_key, dh2): %x\n", decryptKey2)

	// Step 12: Decrypt and verify timestamp
	fmt.Println("\n=== STEP 12: Decrypt and validate timestamp ===")
	decryptedTimestamp, err := chachaPolyDecrypt(decryptKey2, 0, msg.Timestamp[:], state.hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt timestamp: %v", err)
	}
	if len(decryptedTimestamp) != 12 {
		return nil, fmt.Errorf("decrypted timestamp wrong length: got %d, expected 12", len(decryptedTimestamp))
	}
	copy(state.receivedTimestamp[:], decryptedTimestamp)
	fmt.Printf("decrypted_timestamp: %x\n", state.receivedTimestamp)

	// Validate timestamp for replay protection
	state.timestampValid = validateTimestamp(state.receivedTimestamp, lastTimestamp)
	fmt.Printf("timestamp_valid (newer than last): %v\n", state.timestampValid)

	if !state.timestampValid {
		return nil, fmt.Errorf("invalid timestamp - potential replay attack")
	}

	// Step 13: Final hash update (sync with initiator)
	fmt.Println("\n=== STEP 13: Final hash update ===")
	temp5 := append(state.hash[:], msg.Timestamp[:]...)
	state.hash = blake2sHash(temp5)
	fmt.Printf("final_hash = HASH(old_hash || encrypted_timestamp): %x\n", state.hash)

	fmt.Printf("\n=== HANDSHAKE INITIATION PROCESSING COMPLETE ===\n")
	fmt.Printf("Final chaining_key: %x\n", state.chainingKey)
	fmt.Printf("Final hash: %x\n", state.hash)
	fmt.Printf("Initiator static public key: %x\n", state.initiatorStaticPublic)
	fmt.Printf("All validations passed: MAC1=%v, MAC2=%v, Timestamp=%v\n",
		state.mac1Valid, state.mac2Valid, state.timestampValid)

	return state, nil
}

// createHandshakeResponse (Part 3/4) creates the second message of the Noise_IK handshake (responder side)
// Takes the synchronized responder state and completes the handshake by performing final DH operations
// and deriving the transport keys that both sides will use for data encryption
func createHandshakeResponse(responderState *HandshakeResponderState, responderIndex uint32) (*HandshakeResponse, *HandshakeResponderState, error) {

	fmt.Println("🔐 Creating WireGuard Handshake Response (Responder Side)")

	// Step 1: Generate ephemeral keypair for responder
	// This ephemeral key will be used for the final DH operations to derive transport keys
	fmt.Println("\n=== STEP 1: Generate responder ephemeral keypair ===")
	responderEphPriv, responderEphPub, err := generateKeypair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate responder ephemeral keypair: %v", err)
	}
	fmt.Printf("responder_ephemeral_private: %x\n", responderEphPriv)
	fmt.Printf("responder_ephemeral_public: %x\n", responderEphPub)

	// Step 2: Mix responder's ephemeral public key into hash
	// This continues the cryptographic transcript of the handshake
	fmt.Println("\n=== STEP 2: Mix responder ephemeral public key into hash ===")
	temp := append(responderState.hash[:], responderEphPub[:]...)
	responderState.hash = blake2sHash(temp)
	fmt.Printf("hash = HASH(old_hash || responder_ephemeral_public): %x\n", responderState.hash)

	// Step 3: Mix responder's ephemeral public key into chaining key using KDF1
	// This advances the key derivation chain with responder's ephemeral contribution
	fmt.Println("\n=== STEP 3: Mix responder ephemeral public key into chaining key (KDF1) ===")
	newChainingKey1, err := kdf1(responderState.chainingKey[:], responderEphPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf1 failed: %v", err)
	}
	responderState.chainingKey = newChainingKey1
	fmt.Printf("chaining_key = KDF1(old_chaining_key, responder_ephemeral_public): %x\n", responderState.chainingKey)

	// Step 4: Perform ephemeral-ephemeral DH operation
	// This is the first of the final two DH operations that create forward secrecy
	fmt.Println("\n=== STEP 4: DH(responder_ephemeral_private, initiator_ephemeral_public) + KDF1 ===")
	dhResult1, err := dhOperation(responderEphPriv, responderState.initiatorEphemeralPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("DH operation 1 (ephemeral-ephemeral) failed: %v", err)
	}
	fmt.Printf("dh1 = DH(responder_ephemeral_private, initiator_ephemeral_public): %x\n", dhResult1)

	// Mix the ephemeral-ephemeral shared secret into chaining key
	newChainingKey2, err := kdf1(responderState.chainingKey[:], dhResult1[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf1 failed for ephemeral-ephemeral: %v", err)
	}
	responderState.chainingKey = newChainingKey2
	fmt.Printf("chaining_key = KDF1(chaining_key, dh1): %x\n", responderState.chainingKey)

	// Step 5: Perform ephemeral-static DH operation
	// This completes the final DH mixing for perfect forward secrecy
	fmt.Println("\n=== STEP 5: DH(responder_ephemeral_private, initiator_static_public) + KDF1 ===")
	dhResult2, err := dhOperation(responderEphPriv, responderState.initiatorStaticPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("DH operation 2 (ephemeral-static) failed: %v", err)
	}
	fmt.Printf("dh2 = DH(responder_ephemeral_private, initiator_static_public): %x\n", dhResult2)

	// Mix the ephemeral-static shared secret into chaining key
	newChainingKey3, err := kdf1(responderState.chainingKey[:], dhResult2[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf1 failed for ephemeral-static: %v", err)
	}
	responderState.chainingKey = newChainingKey3
	fmt.Printf("chaining_key = KDF1(chaining_key, dh2): %x\n", responderState.chainingKey)

	// Step 6: Mix pre-shared key (zeros for minimal implementation)
	// The PSK provides post-quantum resistance when available
	fmt.Println("\n=== STEP 6: Mix pre-shared key (zeros for minimal version) ===")
	var presharedKey [32]byte // All zeros for minimal implementation
	fmt.Printf("preshared_key (zeros): %x\n", presharedKey)

	// Use KDF3 to derive both the next chaining key and temporary encryption key
	// This is the final key derivation step before transport key generation
	newChainingKey4, temp2, encryptKey, err := kdf3(responderState.chainingKey[:], presharedKey[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf3 failed for preshared key: %v", err)
	}
	responderState.chainingKey = newChainingKey4
	fmt.Printf("chaining_key = KDF3.key1(chaining_key, preshared_key): %x\n", responderState.chainingKey)
	fmt.Printf("temp2 = KDF3.key2(...): %x\n", temp2)
	fmt.Printf("encrypt_key = KDF3.key3(...): %x\n", encryptKey)

	// Mix temp2 into hash to update the cryptographic transcript
	temp3 := append(responderState.hash[:], temp2[:]...)
	responderState.hash = blake2sHash(temp3)
	fmt.Printf("hash = HASH(old_hash || temp2): %x\n", responderState.hash)

	// Step 7: Encrypt empty payload
	// This proves the responder can perform encryption and confirms key derivation
	fmt.Println("\n=== STEP 7: Encrypt empty payload ===")
	var emptyPayload []byte // Empty payload
	fmt.Printf("empty_payload: (0 bytes)\n")
	encryptedEmpty, err := chachaPolyEncrypt(encryptKey, 0, emptyPayload, responderState.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt empty payload: %v", err)
	}
	if len(encryptedEmpty) != 16 { // 0 bytes + 16 byte auth tag
		return nil, nil, fmt.Errorf("encrypted empty payload wrong length: got %d, expected 16", len(encryptedEmpty))
	}
	var encryptedEmptyArray [16]byte
	copy(encryptedEmptyArray[:], encryptedEmpty)
	fmt.Printf("encrypted_empty (16 byte auth tag): %x\n", encryptedEmptyArray)

	// Step 8: Final hash update
	// Complete the cryptographic transcript with the encrypted empty payload
	fmt.Println("\n=== STEP 8: Final hash update ===")
	temp4 := append(responderState.hash[:], encryptedEmpty...)
	responderState.hash = blake2sHash(temp4)
	fmt.Printf("final_hash = HASH(old_hash || encrypted_empty): %x\n", responderState.hash)

	// Step 9: Create the handshake response message
	// This message contains the responder's ephemeral public key and encrypted confirmation
	fmt.Println("\n=== STEP 9: Create HandshakeResponse message ===")
	response := &HandshakeResponse{
		Type:      MessageTypeHandshakeResponse,
		Sender:    responderIndex,                      // Responder's session index
		Receiver:  responderState.initiatorSenderIndex, // Echo back initiator's index
		Ephemeral: responderEphPub,                     // Responder's ephemeral public key
		Empty:     encryptedEmptyArray,                 // Encrypted proof of key derivation
		// MAC1 and MAC2 calculated below
	}

	fmt.Printf("Message type: %d\n", response.Type)
	fmt.Printf("Sender index: %d\n", response.Sender)
	fmt.Printf("Receiver index: %d\n", response.Receiver)
	fmt.Printf("Ephemeral: %x\n", response.Ephemeral)
	fmt.Printf("Empty: %x\n", response.Empty)

	// Step 10: Calculate MAC1 and MAC2 for message authentication
	// MAC1 proves responder knows initiator's static public key
	fmt.Println("\n=== STEP 10: Calculate MAC1 and MAC2 ===")

	// Marshal message without MACs to get bytes for MAC calculation
	responseBytes := response.Marshal()
	msgBytesForMAC1 := responseBytes[:len(responseBytes)-32] // Exclude MAC1(16) + MAC2(16) = 32 bytes

	// Calculate MAC1 using initiator's static public key
	mac1, err := calculateMAC1(msgBytesForMAC1, responderState.initiatorStaticPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate MAC1: %v", err)
	}
	response.MAC1 = mac1
	fmt.Printf("MAC1: %x\n", response.MAC1)

	// Calculate MAC2 (no cookie for minimal implementation)
	responseBytes = response.Marshal()
	msgBytesForMAC2 := responseBytes[:len(responseBytes)-16] // Exclude MAC2(16) bytes
	mac2 := calculateMAC2(msgBytesForMAC2, nil)              // No cookie
	response.MAC2 = mac2
	fmt.Printf("MAC2: %x\n", response.MAC2)

	fmt.Printf("\n=== HANDSHAKE RESPONSE COMPLETE ===\n")
	fmt.Printf("Final chaining_key: %x\n", responderState.chainingKey)
	fmt.Printf("Final hash: %x\n", responderState.hash)

	return response, responderState, nil
}

// processHandshakeResponse (Part 4/4) processes the second handshake message (initiator side)
// This completes the handshake by performing the same DH operations as the responder
// and derives the final transport keys that both sides will use for data encryption
func processHandshakeResponse(responseBytes []byte, initiatorState *HandshakeInitiationState) (*HandshakeInitiationState, error) {

	fmt.Println("🔑 Processing WireGuard Handshake Response (Initiator Side)")

	// Step 1: Unmarshal the received response message
	fmt.Println("\n=== STEP 1: Unmarshal received response message ===")
	var response HandshakeResponse
	if err := response.Unmarshal(responseBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal handshake response: %v", err)
	}

	if response.Type != MessageTypeHandshakeResponse {
		return nil, fmt.Errorf("invalid message type: expected %d, got %d", MessageTypeHandshakeResponse, response.Type)
	}

	// Verify the receiver index matches our sender index
	if response.Receiver != initiatorState.senderIndex {
		return nil, fmt.Errorf("receiver index mismatch: expected %d, got %d", initiatorState.senderIndex, response.Receiver)
	}

	fmt.Printf("Message type: %d\n", response.Type)
	fmt.Printf("Responder sender: %d\n", response.Sender)
	fmt.Printf("Receiver (our sender): %d\n", response.Receiver)
	fmt.Printf("Responder ephemeral: %x\n", response.Ephemeral)
	fmt.Printf("Encrypted empty: %x\n", response.Empty)

	// Step 2: Validate MAC1 - proves responder knows our static public key
	fmt.Println("\n=== STEP 2: Validate MAC1 ===")
	msgBytesForMAC1 := responseBytes[:len(responseBytes)-32] // Exclude MAC1(16) + MAC2(16)
	expectedMAC1, err := calculateMAC1(msgBytesForMAC1, initiatorState.ourStaticPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate expected MAC1: %v", err)
	}

	mac1Valid := (response.MAC1 == expectedMAC1)
	fmt.Printf("Expected MAC1: %x\n", expectedMAC1)
	fmt.Printf("Received MAC1:  %x\n", response.MAC1)
	fmt.Printf("MAC1 valid: %v\n", mac1Valid)

	if !mac1Valid {
		return nil, fmt.Errorf("invalid MAC1 - responder doesn't know our static public key")
	}

	// Step 3: Validate MAC2 (currently just check if zeros)
	fmt.Println("\n=== STEP 3: Validate MAC2 ===")
	var zeroMAC2 [16]byte
	mac2Valid := (response.MAC2 == zeroMAC2)
	fmt.Printf("MAC2: %x\n", response.MAC2)
	fmt.Printf("MAC2 valid (should be zeros): %v\n", mac2Valid)

	// Step 4: Sync cryptographic operations with responder - mix responder's ephemeral
	fmt.Println("\n=== STEP 4: Mix responder ephemeral public key into hash ===")
	temp := append(initiatorState.hash[:], response.Ephemeral[:]...)
	initiatorState.hash = blake2sHash(temp)
	fmt.Printf("hash = HASH(old_hash || responder_ephemeral_public): %x\n", initiatorState.hash)

	// Step 5: Mix responder's ephemeral public key into chaining key using KDF1
	fmt.Println("\n=== STEP 5: Mix responder ephemeral public key into chaining key (KDF1) ===")
	newChainingKey1, err := kdf1(initiatorState.chainingKey[:], response.Ephemeral[:])
	if err != nil {
		return nil, fmt.Errorf("kdf1 failed: %v", err)
	}
	initiatorState.chainingKey = newChainingKey1
	fmt.Printf("chaining_key = KDF1(old_chaining_key, responder_ephemeral_public): %x\n", initiatorState.chainingKey)

	// Step 6: Perform ephemeral-ephemeral DH operation (same as responder did)
	fmt.Println("\n=== STEP 6: DH(our_ephemeral_private, responder_ephemeral_public) + KDF1 ===")
	dhResult1, err := dhOperation(initiatorState.ephemeralPrivate, response.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("DH operation 1 (ephemeral-ephemeral) failed: %v", err)
	}
	fmt.Printf("dh1 = DH(our_ephemeral_private, responder_ephemeral_public): %x\n", dhResult1)

	// Mix the ephemeral-ephemeral shared secret into chaining key
	newChainingKey2, err := kdf1(initiatorState.chainingKey[:], dhResult1[:])
	if err != nil {
		return nil, fmt.Errorf("kdf1 failed for ephemeral-ephemeral: %v", err)
	}
	initiatorState.chainingKey = newChainingKey2
	fmt.Printf("chaining_key = KDF1(chaining_key, dh1): %x\n", initiatorState.chainingKey)

	// Step 7: Perform ephemeral-static DH operation (same as responder did)
	fmt.Println("\n=== STEP 7: DH(our_static_private, responder_ephemeral_public) + KDF1 ===")
	dhResult2, err := dhOperation(initiatorState.ourStaticPrivate, response.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("DH operation 2 (ephemeral-static) failed: %v", err)
	}
	fmt.Printf("dh2 = DH(our_static_private, responder_ephemeral_public): %x\n", dhResult2)

	// Mix the ephemeral-static shared secret into chaining key
	newChainingKey3, err := kdf1(initiatorState.chainingKey[:], dhResult2[:])
	if err != nil {
		return nil, fmt.Errorf("kdf1 failed for ephemeral-static: %v", err)
	}
	initiatorState.chainingKey = newChainingKey3
	fmt.Printf("chaining_key = KDF1(chaining_key, dh2): %x\n", initiatorState.chainingKey)

	// Step 8: Mix pre-shared key (zeros for minimal implementation)
	fmt.Println("\n=== STEP 8: Mix pre-shared key (zeros for minimal version) ===")
	var presharedKey [32]byte // All zeros for minimal implementation
	fmt.Printf("preshared_key (zeros): %x\n", presharedKey)

	// Use KDF3 to derive the same keys as responder did
	newChainingKey4, temp2, decryptKey, err := kdf3(initiatorState.chainingKey[:], presharedKey[:])
	if err != nil {
		return nil, fmt.Errorf("kdf3 failed for preshared key: %v", err)
	}
	initiatorState.chainingKey = newChainingKey4
	fmt.Printf("chaining_key = KDF3.key1(chaining_key, preshared_key): %x\n", initiatorState.chainingKey)
	fmt.Printf("temp2 = KDF3.key2(...): %x\n", temp2)
	fmt.Printf("decrypt_key = KDF3.key3(...): %x\n", decryptKey)

	// Mix temp2 into hash (sync with responder)
	temp3 := append(initiatorState.hash[:], temp2[:]...)
	initiatorState.hash = blake2sHash(temp3)
	fmt.Printf("hash = HASH(old_hash || temp2): %x\n", initiatorState.hash)

	// Step 9: Decrypt and verify empty payload
	fmt.Println("\n=== STEP 9: Decrypt and verify empty payload ===")
	decryptedEmpty, err := chachaPolyDecrypt(decryptKey, 0, response.Empty[:], initiatorState.hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt empty payload: %v", err)
	}

	// Empty payload should be exactly 0 bytes
	emptyPayloadValid := (len(decryptedEmpty) == 0)
	fmt.Printf("decrypted_empty_length: %d bytes\n", len(decryptedEmpty))
	fmt.Printf("empty_payload_valid (should be 0 bytes): %v\n", emptyPayloadValid)

	if !emptyPayloadValid {
		return nil, fmt.Errorf("invalid empty payload - expected 0 bytes, got %d", len(decryptedEmpty))
	}

	// Step 10: Final hash update (sync with responder)
	fmt.Println("\n=== STEP 10: Final hash update ===")
	temp4 := append(initiatorState.hash[:], response.Empty[:]...)
	initiatorState.hash = blake2sHash(temp4)
	fmt.Printf("final_hash = HASH(old_hash || encrypted_empty): %x\n", initiatorState.hash)

	fmt.Printf("\n=== HANDSHAKE RESPONSE PROCESSING COMPLETE ===\n")
	fmt.Printf("Final chaining_key: %x\n", initiatorState.chainingKey)
	fmt.Printf("Final hash: %x\n", initiatorState.hash)
	fmt.Printf("All validations passed: MAC1=%v, MAC2=%v, EmptyPayload=%v\n",
		mac1Valid, mac2Valid, emptyPayloadValid)

	return initiatorState, nil
}

// deriveTransportKeys derives the final send/receive keys from the completed handshake state
// This is called after both sides have completed the handshake protocol
func deriveTransportKeys(finalChainingKey [32]byte) (sendingKey, receivingKey [32]byte, err error) {
	fmt.Println("\n🔐 Deriving Transport Keys from Final Chaining Key")

	// Final key derivation: KDF2 with empty input
	sending, receiving, err := kdf2(finalChainingKey[:], nil)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("transport key derivation failed: %v", err)
	}

	fmt.Printf("sending_key: %x\n", sending)
	fmt.Printf("receiving_key: %x\n", receiving)

	return sending, receiving, nil
}
