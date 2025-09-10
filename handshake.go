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
	"crypto/rand"
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
	ourStaticPrivate  [32]byte
	ourStaticPublic   [32]byte
	peerStaticPublic  [32]byte
	
	// Generated message fields
	senderIndex     uint32
	encryptedStatic    [48]byte // 32 bytes + 16 byte auth tag
	encryptedTimestamp [28]byte // 12 bytes + 16 byte auth tag
	
	// Intermediate values for debugging
	tempKey1 [32]byte
	tempKey2 [32]byte
}

// createHandshakeInitiation creates the first message of the Noise_IK handshake
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
	
	// Step 12: Create the message structure
	fmt.Println("\n=== STEP 12: Create HandshakeInitiation message ===")
	msg := &HandshakeInitiation{
		Type:      MessageTypeHandshakeInitiation,
		Sender:    state.senderIndex,
		Ephemeral: state.ephemeralPublic,
		Static:    state.encryptedStatic,
		Timestamp: state.encryptedTimestamp,
		// MAC1 and MAC2 will be calculated separately
	}
	
	fmt.Printf("Message type: %d\n", msg.Type)
	fmt.Printf("Sender index: %d\n", msg.Sender)
	fmt.Printf("Ephemeral: %x\n", msg.Ephemeral)
	fmt.Printf("Static: %x\n", msg.Static)
	fmt.Printf("Timestamp: %x\n", msg.Timestamp)
	
	fmt.Printf("\n=== HANDSHAKE INITIATION COMPLETE ===\n")
	fmt.Printf("Final chaining_key: %x\n", state.chainingKey)
	fmt.Printf("Final hash: %x\n", state.hash)
	
	return msg, state, nil
}

// testHandshakeInitiation demonstrates the step-by-step handshake initiation
func testHandshakeInitiation() error {
	fmt.Println("🚀 Starting WireGuard Noise_IK Handshake Initiation Test\n")
	
	// Generate keys for testing
	ourPrivKey, ourPubKey, err := generateKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate our keypair: %v", err)
	}
	
	peerPrivKey, peerPubKey, err := generateKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate peer keypair: %v", err)
	}
	
	fmt.Printf("🔑 Generated keys:\n")
	fmt.Printf("Our private key:  %x\n", ourPrivKey)
	fmt.Printf("Our public key:   %x\n", ourPubKey)
	fmt.Printf("Peer private key: %x\n", peerPrivKey)
	fmt.Printf("Peer public key:  %x\n\n", peerPubKey)
	
	// Generate random sender index (normally this would be managed by the WG instance)
	var senderIndexBytes [4]byte
	if _, err := rand.Read(senderIndexBytes[:]); err != nil {
		return fmt.Errorf("failed to generate sender index: %v", err)
	}
	senderIndex := uint32(senderIndexBytes[0]) | 
	               uint32(senderIndexBytes[1])<<8 | 
	               uint32(senderIndexBytes[2])<<16 | 
	               uint32(senderIndexBytes[3])<<24
	
	// Create the handshake initiation
	msg, state, err := createHandshakeInitiation(ourPrivKey, ourPubKey, peerPubKey, senderIndex)
	if err != nil {
		return fmt.Errorf("handshake initiation failed: %v", err)
	}
	
	// Marshal the message to bytes (this would be sent over UDP)
	msgBytes := msg.Marshal()
	fmt.Printf("\n📦 Marshaled message (%d bytes):\n", len(msgBytes))
	fmt.Printf("%x\n", msgBytes)
	
	fmt.Printf("\n✅ Handshake initiation created successfully!\n")
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("  - Message type: %d\n", msg.Type)
	fmt.Printf("  - Sender index: %d\n", msg.Sender)
	fmt.Printf("  - Total message size: %d bytes\n", len(msgBytes))
	fmt.Printf("  - Final chaining key: %x\n", state.chainingKey)
	fmt.Printf("  - Final hash: %x\n", state.hash)
	
	return nil
}