// transport.go
//
// Data packet encryption and decryption for established sessions
//
// Contains:
// - Transport data message encryption (TUN packets -> UDP)
// - Transport data message decryption (UDP -> TUN packets)  
// - Nonce counter management and validation
// - Basic replay protection (simple counter-based)
// - Packet padding and length handling
// - Keepalive message handling (zero-length transport messages)

package main