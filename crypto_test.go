package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestCurve25519Operations tests key generation and DH operations
func TestCurve25519Operations(t *testing.T) {
	t.Run("Key generation", func(t *testing.T) {
		// Generate keypair
		priv, pub, err := generateKeypair()
		if err != nil {
			t.Fatalf("failed to generate keypair: %v", err)
		}

		// Verify key lengths
		if len(priv) != 32 {
			t.Errorf("private key wrong length: expected 32, got %d", len(priv))
		}

		if len(pub) != 32 {
			t.Errorf("public key wrong length: expected 32, got %d", len(pub))
		}

		// Private key should not be all zeros
		var zeroKey [32]byte
		if priv == zeroKey {
			t.Error("private key should not be all zeros")
		}

		// Public key should not be all zeros
		if pub == zeroKey {
			t.Error("public key should not be all zeros")
		}

		// Generate another keypair - should be different
		priv2, pub2, err := generateKeypair()
		if err != nil {
			t.Fatalf("failed to generate second keypair: %v", err)
		}

		if priv == priv2 {
			t.Error("private keys should be different")
		}

		if pub == pub2 {
			t.Error("public keys should be different")
		}
	})

	t.Run("Diffie-Hellman key exchange", func(t *testing.T) {
		// Generate two keypairs
		alicePriv, alicePub, err := generateKeypair()
		if err != nil {
			t.Fatalf("failed to generate Alice's keypair: %v", err)
		}

		bobPriv, bobPub, err := generateKeypair()
		if err != nil {
			t.Fatalf("failed to generate Bob's keypair: %v", err)
		}

		// Perform DH from both sides
		sharedAlice, err := dhOperation(alicePriv, bobPub)
		if err != nil {
			t.Fatalf("Alice's DH operation failed: %v", err)
		}

		sharedBob, err := dhOperation(bobPriv, alicePub)
		if err != nil {
			t.Fatalf("Bob's DH operation failed: %v", err)
		}

		// Shared secrets should be identical
		if sharedAlice != sharedBob {
			t.Error("shared secrets don't match")
		}

		// Shared secret should be 32 bytes
		if len(sharedAlice) != 32 {
			t.Errorf("shared secret wrong length: expected 32, got %d", len(sharedAlice))
		}

		// Shared secret should not be all zeros
		var zeroSecret [32]byte
		if sharedAlice == zeroSecret {
			t.Error("shared secret should not be all zeros")
		}
	})
}

// TestBLAKE2sOperations tests hashing and MAC functions
func TestBLAKE2sOperations(t *testing.T) {
	testData := []byte("The quick brown fox jumps over the lazy dog")

	t.Run("BLAKE2s hashing", func(t *testing.T) {
		hash := blake2sHash(testData)

		// Hash should be 32 bytes
		if len(hash) != 32 {
			t.Errorf("hash wrong length: expected 32, got %d", len(hash))
		}

		// Same input should produce same hash
		hash2 := blake2sHash(testData)
		if hash != hash2 {
			t.Error("hash not deterministic")
		}

		// Different input should produce different hash
		hash3 := blake2sHash([]byte("different data"))
		if hash == hash3 {
			t.Error("different inputs produced same hash")
		}

		// Empty input should still produce valid hash
		emptyHash := blake2sHash([]byte{})
		if len(emptyHash) != 32 {
			t.Error("empty input hash wrong length")
		}
	})

	t.Run("BLAKE2s MAC", func(t *testing.T) {
		key := []byte("test key for MAC")
		
		mac, err := blake2sMac(key, testData)
		if err != nil {
			t.Fatalf("MAC calculation failed: %v", err)
		}

		// MAC should be 16 bytes
		if len(mac) != 16 {
			t.Errorf("MAC wrong length: expected 16, got %d", len(mac))
		}

		// Same key and data should produce same MAC
		mac2, err := blake2sMac(key, testData)
		if err != nil {
			t.Fatalf("second MAC calculation failed: %v", err)
		}

		if mac != mac2 {
			t.Error("MAC not deterministic")
		}

		// Different key should produce different MAC
		mac3, err := blake2sMac([]byte("different key"), testData)
		if err != nil {
			t.Fatalf("third MAC calculation failed: %v", err)
		}

		if mac == mac3 {
			t.Error("different keys produced same MAC")
		}

		// Different data should produce different MAC
		mac4, err := blake2sMac(key, []byte("different data"))
		if err != nil {
			t.Fatalf("fourth MAC calculation failed: %v", err)
		}

		if mac == mac4 {
			t.Error("different data produced same MAC")
		}
	})

	t.Run("BLAKE2s HMAC", func(t *testing.T) {
		key := []byte("test key for HMAC")
		
		hmac, err := blake2sHmac(key, testData)
		if err != nil {
			t.Fatalf("HMAC calculation failed: %v", err)
		}

		// HMAC should be 32 bytes
		if len(hmac) != 32 {
			t.Errorf("HMAC wrong length: expected 32, got %d", len(hmac))
		}

		// Same key and data should produce same HMAC
		hmac2, err := blake2sHmac(key, testData)
		if err != nil {
			t.Fatalf("second HMAC calculation failed: %v", err)
		}

		if hmac != hmac2 {
			t.Error("HMAC not deterministic")
		}

		// Different key should produce different HMAC
		hmac3, err := blake2sHmac([]byte("different key"), testData)
		if err != nil {
			t.Fatalf("third HMAC calculation failed: %v", err)
		}

		if hmac == hmac3 {
			t.Error("different keys produced same HMAC")
		}
	})
}

// TestKeyDerivationFunctions tests KDF1, KDF2, and KDF3
func TestKeyDerivationFunctions(t *testing.T) {
	chainingKey := []byte("test chaining key for derivation")
	inputMaterial := []byte("input material for key derivation")

	t.Run("KDF1", func(t *testing.T) {
		derivedKey, err := kdf1(chainingKey, inputMaterial)
		if err != nil {
			t.Fatalf("KDF1 failed: %v", err)
		}

		// Should produce 32-byte key
		if len(derivedKey) != 32 {
			t.Errorf("KDF1 output wrong length: expected 32, got %d", len(derivedKey))
		}

		// Same inputs should produce same output
		derivedKey2, err := kdf1(chainingKey, inputMaterial)
		if err != nil {
			t.Fatalf("second KDF1 failed: %v", err)
		}

		if derivedKey != derivedKey2 {
			t.Error("KDF1 not deterministic")
		}

		// Different chaining key should produce different output
		derivedKey3, err := kdf1([]byte("different chaining key"), inputMaterial)
		if err != nil {
			t.Fatalf("third KDF1 failed: %v", err)
		}

		if derivedKey == derivedKey3 {
			t.Error("different chaining keys produced same KDF1 output")
		}

		// Different input material should produce different output
		derivedKey4, err := kdf1(chainingKey, []byte("different input"))
		if err != nil {
			t.Fatalf("fourth KDF1 failed: %v", err)
		}

		if derivedKey == derivedKey4 {
			t.Error("different inputs produced same KDF1 output")
		}
	})

	t.Run("KDF2", func(t *testing.T) {
		key1, key2, err := kdf2(chainingKey, inputMaterial)
		if err != nil {
			t.Fatalf("KDF2 failed: %v", err)
		}

		// Should produce two 32-byte keys
		if len(key1) != 32 {
			t.Errorf("KDF2 key1 wrong length: expected 32, got %d", len(key1))
		}

		if len(key2) != 32 {
			t.Errorf("KDF2 key2 wrong length: expected 32, got %d", len(key2))
		}

		// Keys should be different from each other
		if key1 == key2 {
			t.Error("KDF2 produced identical keys")
		}

		// Same inputs should produce same outputs
		key1b, key2b, err := kdf2(chainingKey, inputMaterial)
		if err != nil {
			t.Fatalf("second KDF2 failed: %v", err)
		}

		if key1 != key1b || key2 != key2b {
			t.Error("KDF2 not deterministic")
		}
	})

	t.Run("KDF3", func(t *testing.T) {
		key1, key2, key3, err := kdf3(chainingKey, inputMaterial)
		if err != nil {
			t.Fatalf("KDF3 failed: %v", err)
		}

		// Should produce three 32-byte keys
		if len(key1) != 32 {
			t.Errorf("KDF3 key1 wrong length: expected 32, got %d", len(key1))
		}

		if len(key2) != 32 {
			t.Errorf("KDF3 key2 wrong length: expected 32, got %d", len(key2))
		}

		if len(key3) != 32 {
			t.Errorf("KDF3 key3 wrong length: expected 32, got %d", len(key3))
		}

		// Keys should all be different from each other
		if key1 == key2 || key1 == key3 || key2 == key3 {
			t.Error("KDF3 produced duplicate keys")
		}

		// Same inputs should produce same outputs
		key1b, key2b, key3b, err := kdf3(chainingKey, inputMaterial)
		if err != nil {
			t.Fatalf("second KDF3 failed: %v", err)
		}

		if key1 != key1b || key2 != key2b || key3 != key3b {
			t.Error("KDF3 not deterministic")
		}
	})
}

// TestChaCha20Poly1305AEAD tests authenticated encryption
func TestChaCha20Poly1305AEAD(t *testing.T) {
	// Generate a random key
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	plaintext := []byte("Secret message that needs encryption")
	associatedData := []byte("associated data for authentication")
	nonce := uint64(12345)

	t.Run("Encryption and decryption", func(t *testing.T) {
		// Encrypt
		ciphertext, err := chachaPolyEncrypt(key, nonce, plaintext, associatedData)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Ciphertext should be longer than plaintext (includes auth tag)
		if len(ciphertext) != len(plaintext)+16 {
			t.Errorf("ciphertext wrong length: expected %d, got %d", len(plaintext)+16, len(ciphertext))
		}

		// Decrypt
		decrypted, err := chachaPolyDecrypt(key, nonce, ciphertext, associatedData)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		// Decrypted should match original plaintext
		if !bytes.Equal(decrypted, plaintext) {
			t.Error("decrypted text doesn't match original plaintext")
		}
	})

	t.Run("Different keys produce different ciphertext", func(t *testing.T) {
		var key2 [32]byte
		if _, err := rand.Read(key2[:]); err != nil {
			t.Fatalf("failed to generate second random key: %v", err)
		}

		ciphertext1, err := chachaPolyEncrypt(key, nonce, plaintext, associatedData)
		if err != nil {
			t.Fatalf("first encryption failed: %v", err)
		}

		ciphertext2, err := chachaPolyEncrypt(key2, nonce, plaintext, associatedData)
		if err != nil {
			t.Fatalf("second encryption failed: %v", err)
		}

		if bytes.Equal(ciphertext1, ciphertext2) {
			t.Error("different keys produced identical ciphertext")
		}
	})

	t.Run("Different nonces produce different ciphertext", func(t *testing.T) {
		ciphertext1, err := chachaPolyEncrypt(key, nonce, plaintext, associatedData)
		if err != nil {
			t.Fatalf("first encryption failed: %v", err)
		}

		ciphertext2, err := chachaPolyEncrypt(key, nonce+1, plaintext, associatedData)
		if err != nil {
			t.Fatalf("second encryption failed: %v", err)
		}

		if bytes.Equal(ciphertext1, ciphertext2) {
			t.Error("different nonces produced identical ciphertext")
		}
	})

	t.Run("Authentication failure with wrong key", func(t *testing.T) {
		var wrongKey [32]byte
		if _, err := rand.Read(wrongKey[:]); err != nil {
			t.Fatalf("failed to generate wrong key: %v", err)
		}

		ciphertext, err := chachaPolyEncrypt(key, nonce, plaintext, associatedData)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Try to decrypt with wrong key - should fail
		_, err = chachaPolyDecrypt(wrongKey, nonce, ciphertext, associatedData)
		if err == nil {
			t.Error("decryption should fail with wrong key")
		}
	})

	t.Run("Authentication failure with wrong associated data", func(t *testing.T) {
		ciphertext, err := chachaPolyEncrypt(key, nonce, plaintext, associatedData)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Try to decrypt with wrong associated data - should fail
		wrongAssociatedData := []byte("wrong associated data")
		_, err = chachaPolyDecrypt(key, nonce, ciphertext, wrongAssociatedData)
		if err == nil {
			t.Error("decryption should fail with wrong associated data")
		}
	})

	t.Run("Authentication failure with corrupted ciphertext", func(t *testing.T) {
		ciphertext, err := chachaPolyEncrypt(key, nonce, plaintext, associatedData)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Corrupt the ciphertext
		corruptedCiphertext := make([]byte, len(ciphertext))
		copy(corruptedCiphertext, ciphertext)
		corruptedCiphertext[0] ^= 0x01 // Flip a bit

		// Try to decrypt corrupted ciphertext - should fail
		_, err = chachaPolyDecrypt(key, nonce, corruptedCiphertext, associatedData)
		if err == nil {
			t.Error("decryption should fail with corrupted ciphertext")
		}
	})

	t.Run("Empty plaintext", func(t *testing.T) {
		emptyPlaintext := []byte{}

		ciphertext, err := chachaPolyEncrypt(key, nonce, emptyPlaintext, associatedData)
		if err != nil {
			t.Fatalf("encryption of empty plaintext failed: %v", err)
		}

		// Should still have auth tag
		if len(ciphertext) != 16 {
			t.Errorf("empty plaintext ciphertext wrong length: expected 16, got %d", len(ciphertext))
		}

		decrypted, err := chachaPolyDecrypt(key, nonce, ciphertext, associatedData)
		if err != nil {
			t.Fatalf("decryption of empty plaintext failed: %v", err)
		}

		if len(decrypted) != 0 {
			t.Error("decrypted empty plaintext should be empty")
		}
	})
}

// TestTimestampFunctions tests TAI64N timestamp operations
func TestTimestampFunctions(t *testing.T) {
	t.Run("Timestamp generation", func(t *testing.T) {
		timestamp := generateTimestamp()

		// Should be 12 bytes (8 bytes seconds + 4 bytes nanoseconds)
		if len(timestamp) != 12 {
			t.Errorf("timestamp wrong length: expected 12, got %d", len(timestamp))
		}

		// Generate another timestamp - should be different (or at least not before)
		timestamp2 := generateTimestamp()
		
		// Convert to comparable format for validation
		// (timestamps should generally be increasing)
		time1 := bytes.Compare(timestamp[:], timestamp2[:])
		if time1 > 0 {
			// timestamp2 should not be before timestamp1
			// (allowing equal in case they're generated in same nanosecond)
			t.Error("second timestamp appears to be before first timestamp")
		}
	})

	t.Run("Timestamp validation", func(t *testing.T) {
		// Create test timestamps
		oldTimestamp := [12]byte{0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		newTimestamp := [12]byte{0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
		futureTimestamp := [12]byte{0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		// New timestamp should be valid when compared to older one
		if !validateTimestamp(newTimestamp, oldTimestamp) {
			t.Error("newer timestamp should be valid")
		}

		// Old timestamp should not be valid when compared to newer one
		if validateTimestamp(oldTimestamp, newTimestamp) {
			t.Error("older timestamp should not be valid")
		}

		// Same timestamp should not be valid (replay protection)
		if validateTimestamp(newTimestamp, newTimestamp) {
			t.Error("identical timestamps should not be valid")
		}

		// Future timestamp should be valid
		if !validateTimestamp(futureTimestamp, newTimestamp) {
			t.Error("future timestamp should be valid")
		}
	})
}