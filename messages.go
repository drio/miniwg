// messages.go
//
// Wire format message types and parsing
//
// Contains:
// - Message type constants (initiation=1, response=2, transport=4)
// - HandshakeInitiation struct and marshaling/unmarshaling  
// - HandshakeResponse struct and marshaling/unmarshaling
// - TransportData struct and marshaling/unmarshaling
// - MAC1 computation (using peer's public key)
// - Message parsing and validation functions
// - Binary encoding/decoding utilities

package main

// Protocol constants from WireGuard specification
const (
	CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	IDENTIFIER   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	LABEL_MAC1   = "mac1----"
)