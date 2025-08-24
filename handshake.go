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