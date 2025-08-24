// crypto.go
//
// Cryptographic primitives and key derivation functions
//
// Contains:
// - Curve25519 key generation and ECDH operations
// - BLAKE2s hashing and HMAC functions
// - ChaCha20Poly1305 AEAD encryption/decryption
// - HKDF key derivation (KDF1, KDF2, KDF3 from Noise protocol)
// - TAI64N timestamp generation and validation
// - Utility functions for cryptographic operations

package main