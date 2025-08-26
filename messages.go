// messages.go

package main

import (
	"encoding/binary"
	"errors"
)

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

// Marshal converts HandshakeInitiation to wire format bytes
func (msg *HandshakeInitiation) Marshal() []byte {
	buf := make([]byte, 148)
	
	buf[0] = msg.Type
	// Reserved bytes are already zero
	binary.LittleEndian.PutUint32(buf[4:8], msg.Sender)
	
	copy(buf[8:40], msg.Ephemeral[:])
	copy(buf[40:88], msg.Static[:])
	copy(buf[88:116], msg.Timestamp[:])
	copy(buf[116:132], msg.MAC1[:])
	copy(buf[132:148], msg.MAC2[:])
	
	return buf
}

// Unmarshal parses wire format bytes into HandshakeInitiation
func (msg *HandshakeInitiation) Unmarshal(data []byte) error {
	if len(data) != 148 {
		return errors.New("invalid handshake initiation length")
	}
	
	msg.Type = data[0]
	copy(msg.Reserved[:], data[1:4])
	msg.Sender = binary.LittleEndian.Uint32(data[4:8])
	
	copy(msg.Ephemeral[:], data[8:40])
	copy(msg.Static[:], data[40:88])
	copy(msg.Timestamp[:], data[88:116])
	copy(msg.MAC1[:], data[116:132])
	copy(msg.MAC2[:], data[132:148])
	
	return nil
}

// Marshal converts HandshakeResponse to wire format bytes  
func (msg *HandshakeResponse) Marshal() []byte {
	buf := make([]byte, 92)
	
	buf[0] = msg.Type
	// Reserved bytes are already zero
	binary.LittleEndian.PutUint32(buf[4:8], msg.Sender)
	binary.LittleEndian.PutUint32(buf[8:12], msg.Receiver)
	
	copy(buf[12:44], msg.Ephemeral[:])
	copy(buf[44:60], msg.Empty[:])
	copy(buf[60:76], msg.MAC1[:])
	copy(buf[76:92], msg.MAC2[:])
	
	return buf
}

// Unmarshal parses wire format bytes into HandshakeResponse
func (msg *HandshakeResponse) Unmarshal(data []byte) error {
	if len(data) != 92 {
		return errors.New("invalid handshake response length")
	}
	
	msg.Type = data[0]
	copy(msg.Reserved[:], data[1:4])
	msg.Sender = binary.LittleEndian.Uint32(data[4:8])
	msg.Receiver = binary.LittleEndian.Uint32(data[8:12])
	
	copy(msg.Ephemeral[:], data[12:44])
	copy(msg.Empty[:], data[44:60])
	copy(msg.MAC1[:], data[60:76])
	copy(msg.MAC2[:], data[76:92])
	
	return nil
}

// MarshalTransportData converts TransportData header + payload to bytes
// payload should already be encrypted with auth tag appended
func MarshalTransportData(receiver uint32, counter uint64, encryptedPayload []byte) []byte {
	headerSize := 16
	buf := make([]byte, headerSize+len(encryptedPayload))
	
	buf[0] = MessageTypeTransportData
	// Reserved bytes are already zero  
	binary.LittleEndian.PutUint32(buf[4:8], receiver)
	binary.LittleEndian.PutUint64(buf[8:16], counter)
	
	copy(buf[headerSize:], encryptedPayload)
	return buf
}

// UnmarshalTransportData parses transport message, returns header fields + encrypted payload
func UnmarshalTransportData(data []byte) (receiver uint32, counter uint64, encryptedPayload []byte, err error) {
	if len(data) < 16 {
		return 0, 0, nil, errors.New("transport data too short")
	}
	
	if data[0] != MessageTypeTransportData {
		return 0, 0, nil, errors.New("not a transport data message")
	}
	
	receiver = binary.LittleEndian.Uint32(data[4:8])
	counter = binary.LittleEndian.Uint64(data[8:16])
	encryptedPayload = data[16:]
	
	return receiver, counter, encryptedPayload, nil
}

