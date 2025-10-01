// handshake.go
//
// Noise_IK handshake implementation for WireGuard
//
// WireGuard spec defines 4 distinct operations:
// 1. Initiator creates message 1 (CreateMessageInitiation)
// 2. Responder consumes message 1 (ConsumeMessageInitiation)
// 3. Responder creates message 2 (CreateMessageResponse)
// 4. Initiator consumes message 2 (ConsumeMessageResponse)
//
// Contains:
// - Handshake initiation message creation and processing
// - Handshake response message creation and processing
// - Noise_IK state machine implementation
// - Chaining key and hash computations
// - Static and ephemeral key mixing
// - Transport key derivation after successful handshake

package device

import (
	"fmt"
)

// HandshakeInitiationState holds intermediate values during handshake creation
// This helps us see exactly what's happening at each step
type HandshakeInitiationState struct {
	// Noise_IK state variables
	chainingKey [32]byte // Ci in the spec
	hash        [32]byte // Hi in the spec

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

	tempKey1 [32]byte
	tempKey2 [32]byte
}

// CreateMessageInitiation (Part 1/4) creates the first message of the Noise_IK handshake
// Following the exact steps from WireGuard protocol specification
func CreateMessageInitiation(ourStaticPriv, ourStaticPub, peerStaticPub [32]byte, senderIndex uint32) (*HandshakeInitiation, *HandshakeInitiationState, error) {

	state := &HandshakeInitiationState{
		ourStaticPrivate: ourStaticPriv,
		ourStaticPublic:  ourStaticPub,
		peerStaticPublic: peerStaticPub,
		senderIndex:      senderIndex,
	}

	// Step 1: Initialize with precomputed constants (like WireGuard-Go)
	// hash: A tamper-evident log of everything both parties have seen and agreed upon
	// chainingKey: A secret key vault that
	state.chainingKey = InitialChainKey
	state.hash = InitialHash

	// Step 2: Mix responder's static public key into hash
	// We are starting a transcript that will record everything in the handshake.
	// hash = HASH(InitialHash || responder.static_public)
	mixHash(&state.hash, &state.hash, peerStaticPub[:])

	// Step 3: Generate ephemeral keypair
	// initiator.ephemeral_private = DH_GENERATE()
	ephemeralPriv, ephemeralPub, err := GenerateKeypair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral keypair: %v", err)
	}
	state.ephemeralPrivate = ephemeralPriv
	state.ephemeralPublic = ephemeralPub

	// Step 4: Mix ephemeral public key into hash
	// hash = HASH(hash || ephemeral)
	// We are effectively adding the ephermeral public key to the transcript (state.hash)
	mixHash(&state.hash, &state.hash, state.ephemeralPublic[:])

	// Step 5: Mix ephemeral public key into chaining key using KDF1
	// temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
	// initiator.chaining_key = HMAC(temp, 0x1)
	newChainingKey, err := kdf1(state.chainingKey[:], state.ephemeralPublic[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf1 failed: %v", err)
	}
	state.chainingKey = newChainingKey

	// Step 6: Perform DH with ephemeral private and peer static public
	// Then derive encryption key for static key encryption
	dhResult1, err := dhOperation(state.ephemeralPrivate, state.peerStaticPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("DH operation 1 failed: %v", err)
	}

	// temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
	// initiator.chaining_key = HMAC(temp, 0x1)
	// key = HMAC(temp, initiator.chaining_key || 0x2)
	newChainingKey2, encryptKey1, err := kdf2(state.chainingKey[:], dhResult1[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf2 failed: %v", err)
	}
	state.chainingKey = newChainingKey2
	state.tempKey1 = encryptKey1

	// Step 7: Encrypt static public key
	// msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
	encryptedStatic, err := chachaPolyEncrypt(state.tempKey1, 0, state.ourStaticPublic[:], state.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt static key: %v", err)
	}
	if len(encryptedStatic) != 48 { // 32 bytes + 16 byte auth tag
		return nil, nil, fmt.Errorf("encrypted static key wrong length: got %d, expected 48", len(encryptedStatic))
	}
	copy(state.encryptedStatic[:], encryptedStatic)

	// Step 8: Mix encrypted static into hash
	// hash = HASH(hash || encrypted_static)
	mixHash(&state.hash, &state.hash, state.encryptedStatic[:])

	// Step 9: Perform DH with our static private and peer static public
	// Then derive encryption key for timestamp encryption
	dhResult2, err := dhOperation(state.ourStaticPrivate, state.peerStaticPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("DH operation 2 failed: %v", err)
	}

	// temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
	// initiator.chaining_key = HMAC(temp, 0x1)
	// key = HMAC(temp, initiator.chaining_key || 0x2)
	newChainingKey3, encryptKey2, err := kdf2(state.chainingKey[:], dhResult2[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf2 failed: %v", err)
	}
	state.chainingKey = newChainingKey3
	state.tempKey2 = encryptKey2

	// Step 10: Encrypt timestamp
	// msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
	timestamp, err := generateTimestamp()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate timestamp: %v", err)
	}
	encryptedTimestamp, err := chachaPolyEncrypt(state.tempKey2, 0, timestamp[:], state.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt timestamp: %v", err)
	}
	if len(encryptedTimestamp) != 28 { // 12 bytes + 16 byte auth tag
		return nil, nil, fmt.Errorf("encrypted timestamp wrong length: got %d, expected 28", len(encryptedTimestamp))
	}
	copy(state.encryptedTimestamp[:], encryptedTimestamp)

	// Step 11: Final hash update
	// hash = HASH(hash || encrypted_timestamp)
	mixHash(&state.hash, &state.hash, state.encryptedTimestamp[:])

	// Step 12: Create the message structure
	msg := &HandshakeInitiation{
		Type:      MessageTypeHandshakeInitiation,
		Sender:    state.senderIndex,
		Ephemeral: state.ephemeralPublic,
		Static:    state.encryptedStatic,
		Timestamp: state.encryptedTimestamp,
	}

	// Step 13: Calculate MAC1 and MAC2
	// MAC1: proof of knowledge.
	// For that, hmac the peer static public key.
	// Purpose: Anti-DoS + Stealth (no port mapping)
	// If that MAC1 cannot be recomputed by the peer, it will drop the package
	// Marshal message without MACs to get bytes for MAC calculation
	msgBytes := msg.Marshal()
	msgBytesForMAC1 := msgBytes[:len(msgBytes)-32] // Exclude MAC1(16) + MAC2(16) = 32 bytes

	mac1, err := calculateMAC1(msgBytesForMAC1, state.peerStaticPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate MAC1: %v", err)
	}
	msg.MAC1 = mac1

	msgBytes = msg.Marshal()
	msgBytesForMAC2 := msgBytes[:len(msgBytes)-16]
	// TODO: this is zero for now but if could be a cookie value if the responder sent us
	// a cookie reply message because it is under load.
	mac2 := calculateMAC2(msgBytesForMAC2, nil)
	msg.MAC2 = mac2

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

// ConsumeMessageInitiation (Part 2/4) processes the first handshake message (responder side)
// This implements the reverse of CreateMessageInitiation - it takes the received
// message bytes and performs all the same cryptographic operations to sync state
func ConsumeMessageInitiation(messageBytes []byte, ourStaticPriv, ourStaticPub [32]byte, lastTimestamp [12]byte) (*HandshakeResponderState, error) {

	state := &HandshakeResponderState{
		ourStaticPrivate: ourStaticPriv,
		ourStaticPublic:  ourStaticPub,
	}

	// Step 1: Unmarshal the received message
	var msg HandshakeInitiation
	if err := msg.Unmarshal(messageBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal handshake initiation: %v", err)
	}

	if msg.Type != MessageTypeHandshakeInitiation {
		return nil, fmt.Errorf("invalid message type: expected %d, got %d", MessageTypeHandshakeInitiation, msg.Type)
	}

	state.initiatorSenderIndex = msg.Sender
	state.initiatorEphemeralPublic = msg.Ephemeral

	// Step 2: Validate MAC1 - proves sender knows our static public key
	msgBytesForMAC1 := messageBytes[:len(messageBytes)-32]
	expectedMAC1, err := calculateMAC1(msgBytesForMAC1, state.ourStaticPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate expected MAC1: %v", err)
	}

	state.mac1Valid = (msg.MAC1 == expectedMAC1)

	if !state.mac1Valid {
		return nil, fmt.Errorf("invalid MAC1 - sender doesn't know our static public key")
	}

	// Step 3: Validate MAC2 (currently just check if zeros)
	var zeroMAC2 [16]byte
	state.mac2Valid = (msg.MAC2 == zeroMAC2)

	if !state.mac2Valid {
		return nil, fmt.Errorf("invalid MAC2 - expected zeros for minimal implementation")
	}

	// Step 4: Initialize with precomputed constants (like WireGuard-Go)
	state.chainingKey = InitialChainKey

	// Step 5: Initialize hash with our (responder's) static public key
	// This matches WireGuard-Go's ConsumeMessageInitiation line 260
	// hash = HASH(InitialHash || responder.static_public)
	mixHash(&state.hash, &InitialHash, state.ourStaticPublic[:])

	// Step 6: Mix received ephemeral public key into hash
	// hash = HASH(hash || ephemeral) - matches WireGuard-Go line 261
	mixHash(&state.hash, &state.hash, state.initiatorEphemeralPublic[:])

	// Step 7: Mix ephemeral public key into chaining key using KDF1
	// This matches WireGuard-Go's mixKey operation line 262
	newChainingKey, err := kdf1(state.chainingKey[:], state.initiatorEphemeralPublic[:])
	if err != nil {
		return nil, fmt.Errorf("kdf1 failed: %v", err)
	}
	state.chainingKey = newChainingKey

	// Step 8: Perform DH and derive key for static decryption
	dhResult1, err := dhOperation(state.ourStaticPrivate, state.initiatorEphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("DH operation 1 failed: %v", err)
	}

	newChainingKey2, decryptKey1, err := kdf2(state.chainingKey[:], dhResult1[:])
	if err != nil {
		return nil, fmt.Errorf("kdf2 failed: %v", err)
	}
	state.chainingKey = newChainingKey2

	// Step 9: Decrypt and verify initiator's static public key
	decryptedStatic, err := chachaPolyDecrypt(decryptKey1, 0, msg.Static[:], state.hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt static key: %v", err)
	}
	if len(decryptedStatic) != 32 {
		return nil, fmt.Errorf("decrypted static key wrong length: got %d, expected 32", len(decryptedStatic))
	}
	copy(state.initiatorStaticPublic[:], decryptedStatic)

	// Step 10: Mix encrypted static into hash
	// hash = HASH(hash || encrypted_static)
	mixHash(&state.hash, &state.hash, msg.Static[:])

	// Step 11: Perform DH and derive key for timestamp decryption
	dhResult2, err := dhOperation(state.ourStaticPrivate, state.initiatorStaticPublic)
	if err != nil {
		return nil, fmt.Errorf("DH operation 2 failed: %v", err)
	}

	newChainingKey3, decryptKey2, err := kdf2(state.chainingKey[:], dhResult2[:])
	if err != nil {
		return nil, fmt.Errorf("kdf2 failed: %v", err)
	}
	state.chainingKey = newChainingKey3

	// Step 12: Decrypt and verify timestamp
	decryptedTimestamp, err := chachaPolyDecrypt(decryptKey2, 0, msg.Timestamp[:], state.hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt timestamp: %v", err)
	}
	if len(decryptedTimestamp) != 12 {
		return nil, fmt.Errorf("decrypted timestamp wrong length: got %d, expected 12", len(decryptedTimestamp))
	}
	copy(state.receivedTimestamp[:], decryptedTimestamp)

	state.timestampValid = validateTimestamp(state.receivedTimestamp, lastTimestamp)

	if !state.timestampValid {
		return nil, fmt.Errorf("invalid timestamp - potential replay attack")
	}

	// Step 13: Final hash update
	// hash = HASH(hash || encrypted_timestamp)
	mixHash(&state.hash, &state.hash, msg.Timestamp[:])

	return state, nil
}

// CreateMessageResponse (Part 3/4) creates the second message of the Noise_IK handshake (responder side)
// Takes the synchronized responder state and completes the handshake by performing final DH operations
// and deriving the transport keys that both sides will use for data encryption
func CreateMessageResponse(responderState *HandshakeResponderState, responderIndex uint32) (*HandshakeResponse, *HandshakeResponderState, error) {

	// Step 1: Generate ephemeral keypair for responder
	// This ephemeral key will be used for the final DH operations to derive transport keys
	responderEphPriv, responderEphPub, err := GenerateKeypair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate responder ephemeral keypair: %v", err)
	}

	// Step 2: Mix responder's ephemeral public key into hash
	// hash = HASH(hash || responder_ephemeral)
	mixHash(&responderState.hash, &responderState.hash, responderEphPub[:])

	// Step 3: Mix responder's ephemeral public key into chaining key using KDF1
	// This advances the key derivation chain with responder's ephemeral contribution
	newChainingKey1, err := kdf1(responderState.chainingKey[:], responderEphPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf1 failed: %v", err)
	}
	responderState.chainingKey = newChainingKey1

	// Step 4: Perform ephemeral-ephemeral DH operation
	// This is the first of the final two DH operations that create forward secrecy
	dhResult1, err := dhOperation(responderEphPriv, responderState.initiatorEphemeralPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("DH operation 1 (ephemeral-ephemeral) failed: %v", err)
	}

	// Mix the ephemeral-ephemeral shared secret into chaining key
	newChainingKey2, err := kdf1(responderState.chainingKey[:], dhResult1[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf1 failed for ephemeral-ephemeral: %v", err)
	}
	responderState.chainingKey = newChainingKey2

	// Step 5: Perform ephemeral-static DH operation
	// This completes the final DH mixing for perfect forward secrecy
	dhResult2, err := dhOperation(responderEphPriv, responderState.initiatorStaticPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("DH operation 2 (ephemeral-static) failed: %v", err)
	}

	// Mix the ephemeral-static shared secret into chaining key
	newChainingKey3, err := kdf1(responderState.chainingKey[:], dhResult2[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf1 failed for ephemeral-static: %v", err)
	}
	responderState.chainingKey = newChainingKey3

	// Step 6: Mix pre-shared key (zeros for minimal implementation)
	// The PSK provides post-quantum resistance when available
	var presharedKey [32]byte // All zeros for minimal implementation

	// This is the final key derivation step before transport key generation
	newChainingKey4, temp2, encryptKey, err := kdf3(responderState.chainingKey[:], presharedKey[:])
	if err != nil {
		return nil, nil, fmt.Errorf("kdf3 failed for preshared key: %v", err)
	}
	responderState.chainingKey = newChainingKey4

	// Mix temp2 into hash to update the cryptographic transcript
	// hash = HASH(hash || tau)
	mixHash(&responderState.hash, &responderState.hash, temp2[:])

	// Step 7: Encrypt empty payload
	// This proves the responder can perform encryption and confirms key derivation
	var emptyPayload []byte // Empty payload
	encryptedEmpty, err := chachaPolyEncrypt(encryptKey, 0, emptyPayload, responderState.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt empty payload: %v", err)
	}
	if len(encryptedEmpty) != 16 { // 0 bytes + 16 byte auth tag
		return nil, nil, fmt.Errorf("encrypted empty payload wrong length: got %d, expected 16", len(encryptedEmpty))
	}
	var encryptedEmptyArray [16]byte
	copy(encryptedEmptyArray[:], encryptedEmpty)

	// Step 8: Final hash update
	// hash = HASH(hash || encrypted_empty)
	mixHash(&responderState.hash, &responderState.hash, encryptedEmpty)

	// Step 9: Create the handshake response message
	// This message contains the responder's ephemeral public key and encrypted confirmation
	response := &HandshakeResponse{
		Type:      MessageTypeHandshakeResponse,
		Sender:    responderIndex,                      // Responder's session index
		Receiver:  responderState.initiatorSenderIndex, // Echo back initiator's index
		Ephemeral: responderEphPub,                     // Responder's ephemeral public key
		Empty:     encryptedEmptyArray,                 // Encrypted proof of key derivation
		// MAC1 and MAC2 calculated below
	}

	// Step 10: Calculate MAC1 and MAC2 for message authentication
	// MAC1 proves responder knows initiator's static public key

	// Marshal message without MACs to get bytes for MAC calculation
	responseBytes := response.Marshal()
	msgBytesForMAC1 := responseBytes[:len(responseBytes)-32] // Exclude MAC1(16) + MAC2(16) = 32 bytes

	// Calculate MAC1 using initiator's static public key
	mac1, err := calculateMAC1(msgBytesForMAC1, responderState.initiatorStaticPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate MAC1: %v", err)
	}
	response.MAC1 = mac1

	// Calculate MAC2 (no cookie for minimal implementation)
	responseBytes = response.Marshal()
	msgBytesForMAC2 := responseBytes[:len(responseBytes)-16] // Exclude MAC2(16) bytes
	mac2 := calculateMAC2(msgBytesForMAC2, nil)              // No cookie
	response.MAC2 = mac2

	return response, responderState, nil
}

// ConsumeMessageResponse (Part 4/4) processes the second handshake message (initiator side)
// This completes the handshake by performing the same DH operations as the responder
// and derives the final transport keys that both sides will use for data encryption
func ConsumeMessageResponse(responseBytes []byte, initiatorState *HandshakeInitiationState) (*HandshakeInitiationState, error) {

	// Step 1: Unmarshal the received response message
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

	// Step 2: Validate MAC1 - proves responder knows our static public key
	msgBytesForMAC1 := responseBytes[:len(responseBytes)-32] // Exclude MAC1(16) + MAC2(16)
	expectedMAC1, err := calculateMAC1(msgBytesForMAC1, initiatorState.ourStaticPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate expected MAC1: %v", err)
	}

	mac1Valid := (response.MAC1 == expectedMAC1)

	if !mac1Valid {
		return nil, fmt.Errorf("invalid MAC1 - responder doesn't know our static public key")
	}

	// Step 3: Validate MAC2 (currently just check if zeros)
	var zeroMAC2 [16]byte
	mac2Valid := (response.MAC2 == zeroMAC2)

	if !mac2Valid {
		return nil, fmt.Errorf("invalid MAC2 - expected zeros for minimal implementation")
	}

	// Step 4: Sync cryptographic operations with responder
	// hash = HASH(hash || responder_ephemeral)
	mixHash(&initiatorState.hash, &initiatorState.hash, response.Ephemeral[:])

	// Step 5: Mix responder's ephemeral public key into chaining key using KDF1
	newChainingKey1, err := kdf1(initiatorState.chainingKey[:], response.Ephemeral[:])
	if err != nil {
		return nil, fmt.Errorf("kdf1 failed: %v", err)
	}
	initiatorState.chainingKey = newChainingKey1

	// Step 6: Perform ephemeral-ephemeral DH operation (same as responder did)
	dhResult1, err := dhOperation(initiatorState.ephemeralPrivate, response.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("DH operation 1 (ephemeral-ephemeral) failed: %v", err)
	}

	// Mix the ephemeral-ephemeral shared secret into chaining key
	newChainingKey2, err := kdf1(initiatorState.chainingKey[:], dhResult1[:])
	if err != nil {
		return nil, fmt.Errorf("kdf1 failed for ephemeral-ephemeral: %v", err)
	}
	initiatorState.chainingKey = newChainingKey2

	// Step 7: Perform ephemeral-static DH operation (same as responder did)
	dhResult2, err := dhOperation(initiatorState.ourStaticPrivate, response.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("DH operation 2 (ephemeral-static) failed: %v", err)
	}

	// Mix the ephemeral-static shared secret into chaining key
	newChainingKey3, err := kdf1(initiatorState.chainingKey[:], dhResult2[:])
	if err != nil {
		return nil, fmt.Errorf("kdf1 failed for ephemeral-static: %v", err)
	}
	initiatorState.chainingKey = newChainingKey3

	// Step 8: Mix pre-shared key (zeros for minimal implementation)
	var presharedKey [32]byte // All zeros for minimal implementation

	newChainingKey4, temp2, decryptKey, err := kdf3(initiatorState.chainingKey[:], presharedKey[:])
	if err != nil {
		return nil, fmt.Errorf("kdf3 failed for preshared key: %v", err)
	}
	initiatorState.chainingKey = newChainingKey4

	// Mix temp2 into hash (sync with responder)
	// hash = HASH(hash || tau)
	mixHash(&initiatorState.hash, &initiatorState.hash, temp2[:])

	// Step 9: Decrypt and verify empty payload
	decryptedEmpty, err := chachaPolyDecrypt(decryptKey, 0, response.Empty[:], initiatorState.hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt empty payload: %v", err)
	}

	// Empty payload should be exactly 0 bytes
	emptyPayloadValid := (len(decryptedEmpty) == 0)

	if !emptyPayloadValid {
		return nil, fmt.Errorf("invalid empty payload - expected 0 bytes, got %d", len(decryptedEmpty))
	}

	// Step 10: Final hash update (sync with responder)
	// hash = HASH(hash || encrypted_empty)
	mixHash(&initiatorState.hash, &initiatorState.hash, response.Empty[:])

	return initiatorState, nil
}

// deriveTransportKeys derives the final send/receive keys from the completed handshake state
// This is called after both sides have completed the handshake protocol
func deriveTransportKeys(finalChainingKey [32]byte) (sendingKey, receivingKey [32]byte, err error) {

	// Final key derivation: KDF2 with empty input
	sending, receiving, err := kdf2(finalChainingKey[:], nil)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("transport key derivation failed: %v", err)
	}

	return sending, receiving, nil
}
