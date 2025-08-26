// messages.go

package main

// Protocol constants from WireGuard specification
const (
	CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	IDENTIFIER   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	LABEL_MAC1   = "mac1----"
)

// Message type constants
const (
	MessageTypeHandshakeInitiation = 1
	MessageTypeHandshakeResponse   = 2
	MessageTypeTransportData       = 4
)

// HandshakeInitiation is the first message of the Noise_IK handshake
// Total size: 148 bytes
type HandshakeInitiation struct {
	Type     uint8    // Always 1 for handshake initiation
	Reserved [3]uint8 // Must be zero, reserved for future use
	Sender   uint32   // Random index identifying this session (little-endian)

	Ephemeral [32]uint8 // Ephemeral public key generated for this handshake
	Static    [48]uint8 // Encrypted static public key (32 bytes + 16 byte auth tag)
	Timestamp [28]uint8 // Encrypted TAI64N timestamp (12 bytes + 16 byte auth tag)

	MAC1 [16]uint8 // First MAC using peer's static public key
	MAC2 [16]uint8 // Second MAC using cookie (zeros for minimal version)
}

// HandshakeResponse is the second message of the Noise_IK handshake
// Total size: 92 bytes
type HandshakeResponse struct {
	Type     uint8    // Always 2 for handshake response
	Reserved [3]uint8 // Must be zero, reserved for future use
	Sender   uint32   // Random index identifying responder's session
	Receiver uint32   // Echo back the initiator's sender index

	Ephemeral [32]uint8 // Responder's ephemeral public key
	Empty     [16]uint8 // Encrypted empty payload (0 bytes + 16 byte auth tag)

	MAC1 [16]uint8 // First MAC using initiator's static public key
	MAC2 [16]uint8 // Second MAC using cookie (zeros for minimal version)
}

// TransportData carries encrypted tunnel traffic
// Variable size: 16 byte header + encrypted payload
type TransportData struct {
	Type     uint8    // Always 4 for transport data
	Reserved [3]uint8 // Must be zero, reserved for future use
	Receiver uint32   // Index identifying which session to decrypt with
	Counter  uint64   // Nonce counter for ChaCha20Poly1305 (little-endian)

	// Encrypted payload follows (variable length)
	// Format: encrypted_packet + 16-byte Poly1305 auth tag
}

