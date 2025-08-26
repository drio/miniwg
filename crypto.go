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

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// generateKeypair creates a new Curve25519 keypair
func generateKeypair() ([32]byte, [32]byte, error) {
	var privateKey, publicKey [32]byte

	// Generate 32 random bytes for private key
	if _, err := rand.Read(privateKey[:]); err != nil {
		return privateKey, publicKey, err
	}

	// Derive public key from private key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return privateKey, publicKey, nil
}

// dhOperation performs Curve25519 point multiplication (ECDH)
func dhOperation(privateKey, publicKey [32]byte) ([32]byte, error) {
	var sharedSecret [32]byte

	// Perform DH: privateKey * publicKey
	curve25519.ScalarMult(&sharedSecret, &privateKey, &publicKey)

	return sharedSecret, nil
}

// blake2sHash computes BLAKE2s hash (32 bytes output)
func blake2sHash(input []byte) [32]byte {
	var result [32]byte
	hash := blake2s.Sum256(input)
	copy(result[:], hash[:])
	return result
}

// blake2sMac computes keyed BLAKE2s MAC (16 bytes output)
func blake2sMac(key []byte, input []byte) ([16]byte, error) {
	var result [16]byte

	// Create keyed BLAKE2s with 16-byte output
	h, err := blake2s.New128(key)
	if err != nil {
		return result, err
	}

	h.Write(input)
	copy(result[:], h.Sum(nil))
	return result, nil
}

// blake2sHmac computes HMAC using BLAKE2s (32 bytes output)
// HMAC provides message authentication - ensures data integrity and authenticity
// My view of HMAC as a newbie cryptographer:
// When we use HMAC we are basically passing our messages + a key to generate
// the output right? So anyone with the key can confirm that the message comes
// from us and hasn't been modified.
// Used in HKDF key derivation and chaining key computations in Noise protocol
func blake2sHmac(key []byte, input []byte) ([32]byte, error) {
	var result [32]byte

	// Create keyed BLAKE2s with 32-byte output
	h, err := blake2s.New256(key)
	if err != nil {
		return result, err
	}

	h.Write(input)
	copy(result[:], h.Sum(nil))
	return result, nil
}

// kdf1 derives one key using HKDF
// My view of HKDF as a newbie cryptographer:
// HKDF is like a "key stretcher" - you give it some key material and it 
// generates new, independent keys from it. It's the secure way to turn one
// secret into multiple secrets for different purposes.
//
// Why do we have kdf1, kdf2, kdf3? Different steps in WireGuard need different
// numbers of keys:
// - kdf1: Update chaining key (1 output needed)  
// - kdf2: Final transport key derivation (2 keys: send + receive)
// - kdf3: Handshake response mixing (3 keys: chaining + 2 temp keys)
//
// What is "chaining"? It's like a cryptographic ledger of everything we've done:
// Start: chaining_key = HASH("Noise_IK...")  
// Step 1: chaining_key = HKDF(chaining_key, ephemeral_public_key)
// Step 2: chaining_key = HKDF(chaining_key, DH_result_1) 
// Step 3: chaining_key = HKDF(chaining_key, DH_result_2)
// Each step "records" new information into the ledger. The final chaining_key 
// contains cryptographic evidence of ALL handshake steps - that's what makes 
// the transport keys secure and authenticated.
func kdf1(key []byte, input []byte) ([32]byte, error) {
	var result [32]byte
	
	// Step 1: Extract - create a strong key from input material
	extracted, err := blake2sHmac(key, input)
	if err != nil {
		return result, err
	}
	
	// Step 2: Expand - generate output key
	expanded, err := blake2sHmac(extracted[:], []byte{0x1})
	if err != nil {
		return result, err
	}
	
	copy(result[:], expanded[:])
	return result, nil
}

// kdf2 derives two keys using HKDF
// Generates two independent keys from the same source material
func kdf2(key []byte, input []byte) ([32]byte, [32]byte, error) {
	var key1, key2 [32]byte
	
	// Extract phase
	extracted, err := blake2sHmac(key, input)
	if err != nil {
		return key1, key2, err
	}
	
	// Expand phase - generate first key
	temp1, err := blake2sHmac(extracted[:], []byte{0x1})
	if err != nil {
		return key1, key2, err
	}
	copy(key1[:], temp1[:])
	
	// Expand phase - generate second key  
	temp2, err := blake2sHmac(extracted[:], append(temp1[:], 0x2))
	if err != nil {
		return key1, key2, err
	}
	copy(key2[:], temp2[:])
	
	return key1, key2, nil
}

// kdf3 derives three keys using HKDF
// Used in handshake response to derive chaining key + two encryption keys
func kdf3(key []byte, input []byte) ([32]byte, [32]byte, [32]byte, error) {
	var key1, key2, key3 [32]byte
	
	// Extract phase
	extracted, err := blake2sHmac(key, input)
	if err != nil {
		return key1, key2, key3, err
	}
	
	// Expand to get first key
	temp1, err := blake2sHmac(extracted[:], []byte{0x1})
	if err != nil {
		return key1, key2, key3, err
	}
	copy(key1[:], temp1[:])
	
	// Expand to get second key
	temp2, err := blake2sHmac(extracted[:], append(temp1[:], 0x2))
	if err != nil {
		return key1, key2, key3, err
	}
	copy(key2[:], temp2[:])
	
	// Expand to get third key
	temp3, err := blake2sHmac(extracted[:], append(temp2[:], 0x3))
	if err != nil {
		return key1, key2, key3, err
	}
	copy(key3[:], temp3[:])
	
	return key1, key2, key3, nil
}

// chachaPolyEncrypt encrypts using ChaCha20Poly1305 AEAD
// My view of AEAD as a newbie cryptographer:
// AEAD = "Authenticated Encryption with Associated Data". It's like a magical
// box that encrypts your data AND proves it hasn't been tampered with. You
// put in plaintext + a key + a nonce, and get back ciphertext that only 
// someone with the key can decrypt AND verify as authentic.
// The "associated data" is extra info that gets authenticated but not encrypted.
func chachaPolyEncrypt(key [32]byte, nonce uint64, plaintext []byte, additionalData []byte) ([]byte, error) {
	// Create ChaCha20Poly1305 cipher
	cipher, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	
	// WireGuard nonce format: 4 bytes zeros + 8 bytes little-endian counter
	var nonceBytes [12]byte
	binary.LittleEndian.PutUint64(nonceBytes[4:], nonce)
	
	// Encrypt and authenticate
	ciphertext := cipher.Seal(nil, nonceBytes[:], plaintext, additionalData)
	
	return ciphertext, nil
}

// chachaPolyDecrypt decrypts using ChaCha20Poly1305 AEAD
// This verifies authenticity AND decrypts - if someone tampered with the
// ciphertext, this will fail with an error instead of returning garbage.
func chachaPolyDecrypt(key [32]byte, nonce uint64, ciphertext []byte, additionalData []byte) ([]byte, error) {
	// Create ChaCha20Poly1305 cipher
	cipher, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	
	// WireGuard nonce format: 4 bytes zeros + 8 bytes little-endian counter
	var nonceBytes [12]byte
	binary.LittleEndian.PutUint64(nonceBytes[4:], nonce)
	
	// Decrypt and verify authenticity
	plaintext, err := cipher.Open(nil, nonceBytes[:], ciphertext, additionalData)
	if err != nil {
		return nil, err // Authentication failed or ciphertext corrupted
	}
	
	return plaintext, nil
}

// generateTimestamp creates TAI64N timestamp
// My view of TAI64N as a newbie cryptographer:
// TAI64N is just a fancy way to write "time" that prevents replay attacks.
// It's 12 bytes: first 8 bytes = seconds since 1970, last 4 bytes = nanoseconds.
// The key property: it must ALWAYS increase. If we see a timestamp that's 
// older than the last one from a peer, we reject it as a replay attack.
func generateTimestamp() [12]byte {
	var timestamp [12]byte
	
	// Get current time
	now := time.Now()
	
	// TAI64N format:
	// Bytes 0-7: seconds since 1970 TAI (big-endian)
	// Bytes 8-11: nanoseconds within that second (big-endian)
	seconds := uint64(now.Unix())
	nanoseconds := uint32(now.Nanosecond())
	
	// Store in big-endian format (TAI64N standard)
	binary.BigEndian.PutUint64(timestamp[0:8], seconds)
	binary.BigEndian.PutUint32(timestamp[8:12], nanoseconds)
	
	return timestamp
}

// validateTimestamp checks if timestamp is newer than last seen
// This is critical for preventing replay attacks - we must reject any
// handshake initiation with a timestamp we've seen before from this peer.
func validateTimestamp(newTimestamp, lastTimestamp [12]byte) bool {
	// Compare as big-endian integers - since TAI64N is big-endian,
	// we can use byte comparison to check if newTimestamp > lastTimestamp
	for i := 0; i < 12; i++ {
		if newTimestamp[i] > lastTimestamp[i] {
			return true // New timestamp is greater
		} else if newTimestamp[i] < lastTimestamp[i] {
			return false // New timestamp is smaller
		}
		// If equal, continue to next byte
	}
	// All bytes equal - this is a replay!
	return false
}

