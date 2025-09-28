package device

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestCurve25519Operations tests key generation and DH operations
func TestCurve25519Operations(t *testing.T) {
	t.Run("Key generation", func(t *testing.T) {
		priv, pub, err := GenerateKeypair()
		if err != nil {
			t.Fatalf("failed to generate keypair: %v", err)
		}

		priv2, pub2, err := GenerateKeypair()
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
		alicePriv, alicePub, err := GenerateKeypair()
		if err != nil {
			t.Fatalf("failed to generate Alice's keypair: %v", err)
		}

		bobPriv, bobPub, err := GenerateKeypair()
		if err != nil {
			t.Fatalf("failed to generate Bob's keypair: %v", err)
		}

		sharedAlice, err := dhOperation(alicePriv, bobPub)
		if err != nil {
			t.Fatalf("Alice's DH operation failed: %v", err)
		}

		sharedBob, err := dhOperation(bobPriv, alicePub)
		if err != nil {
			t.Fatalf("Bob's DH operation failed: %v", err)
		}

		if sharedAlice != sharedBob {
			t.Error("shared secrets don't match")
		}

	})
}

// TestBLAKE2sOperations tests hashing and MAC functions
func TestBLAKE2sOperations(t *testing.T) {
	testData := []byte("The quick brown fox jumps over the lazy dog")

	t.Run("BLAKE2s hashing", func(t *testing.T) {
		hash := blake2sHash(testData)

		hash3 := blake2sHash([]byte("different data"))
		if hash == hash3 {
			t.Error("different inputs produced same hash")
		}
	})

	// MAC (Message Authentication Code) Authentication Flow:
	//
	// Sender side:
	//   message := "Transfer $100 to Bob"
	//   mac := blake2sMac(shared_key, message)
	//   send(message, mac)  // Both transmitted in plaintext
	//
	// Receiver side:
	//   expected_mac := blake2sMac(shared_key, received_message)
	//   if received_mac == expected_mac {
	//       // ✅ Message is authentic (came from holder of shared_key)
	//       // ✅ Message has integrity (wasn't modified in transit)
	//   }
	//
	// Security properties:
	// - Message content is visible to eavesdroppers
	// - Only someone with the shared key can generate valid MACs
	// - Any tampering with the message produces a different MAC
	// - Provides cryptographic proof of authenticity and integrity
	t.Run("BLAKE2s MAC", func(t *testing.T) {
		key := []byte("test key for MAC")

		mac, err := blake2sMac(key, testData)
		if err != nil {
			t.Fatalf("MAC calculation failed: %v", err)
		}

		mac3, err := blake2sMac([]byte("different key"), testData)
		if err != nil {
			t.Fatalf("third MAC calculation failed: %v", err)
		}

		if mac == mac3 {
			t.Error("different keys produced same MAC")
		}

		mac4, err := blake2sMac(key, []byte("different data"))
		if err != nil {
			t.Fatalf("fourth MAC calculation failed: %v", err)
		}

		if mac == mac4 {
			t.Error("different data produced same MAC")
		}
	})

	// It is more computationally intensive
	t.Run("BLAKE2s HMAC", func(t *testing.T) {
		key := []byte("test key for HMAC")

		hmac, err := blake2sHmac(key, testData)
		if err != nil {
			t.Fatalf("HMAC calculation failed: %v", err)
		}

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
//
// KDFs (Key Derivation Functions) are like a "key factory" - they take existing
// key material and produce new, independent keys for different purposes.
//
// Why we need this: During the WireGuard handshake, we collect multiple secrets
// (ephemeral keys, shared secrets from DH operations) and need to derive separate
// encryption keys from them.
//
// The chainingKey acts like a running ledger that accumulates all cryptographic
// material processed so far. Each step adds new material to this ledger, ensuring
// both peers follow the exact same cryptographic path and derive identical keys.
//
// Security property: Since the chainingKey is used in every step, if any part of
// the handshake is compromised or corrupted (wrong keys, network errors, attacks),
// the entire handshake will fail. This is intentional - it provides automatic
// detection of any problems and prevents partial compromises.
//
// KDF1/KDF2/KDF3 produce different numbers of output keys:
// - KDF1: 1 output key
// - KDF2: 2 output keys
// - KDF3: 3 output keys
//
// What those keys are used for (chaining key, encryption key, etc.)
// depends on the specific step in the WireGuard protocol.
func TestKeyDerivationFunctions(t *testing.T) {
	chainingKey := []byte("test chaining key for derivation")
	inputMaterial := []byte("input material for key derivation")

	t.Run("KDF1", func(t *testing.T) {
		derivedKey, err := kdf1(chainingKey, inputMaterial)
		if err != nil {
			t.Fatalf("KDF1 failed: %v", err)
		}

		derivedKey3, err := kdf1([]byte("different chaining key"), inputMaterial)
		if err != nil {
			t.Fatalf("third KDF1 failed: %v", err)
		}

		if derivedKey == derivedKey3 {
			t.Error("different chaining keys produced same KDF1 output")
		}

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

		if key1 == key2 {
			t.Error("KDF2 produced identical keys")
		}
	})

	t.Run("KDF3", func(t *testing.T) {
		key1, key2, key3, err := kdf3(chainingKey, inputMaterial)
		if err != nil {
			t.Fatalf("KDF3 failed: %v", err)
		}

		if key1 == key2 || key1 == key3 || key2 == key3 {
			t.Error("KDF3 produced duplicate keys")
		}
	})
}

// TestChaCha20Poly1305AEAD tests authenticated encryption
//
// ChaCha20-Poly1305 provides both confidentiality (encryption) and authenticity
// (authentication) in one operation. This is what encrypts all WireGuard traffic
// after the handshake completes.
//
// Two algorithms working together:
// - ChaCha20: Encrypts the plaintext (hides content)
// - Poly1305: Authenticates ciphertext + associated data (detects tampering)
func TestChaCha20Poly1305AEAD(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	plaintext := []byte("Secret message that needs encryption")
	associatedData := []byte("associated data for authentication")
	nonce := uint64(12345)

	t.Run("Encryption and decryption", func(t *testing.T) {
		ciphertext, err := chachaPolyEncrypt(key, nonce, plaintext, associatedData)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := chachaPolyDecrypt(key, nonce, ciphertext, associatedData)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

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

		_, err = chachaPolyDecrypt(wrongKey, nonce, ciphertext, associatedData)
		if err == nil {
			t.Error("decryption should fail with wrong key")
		}
	})

	t.Run("Authentication failure with wrong associated data", func(t *testing.T) {
		// Associated data is transmitted in plaintext but is cryptographically
		// authenticated. Any tampering with it will cause decryption to fail.
		ciphertext, err := chachaPolyEncrypt(key, nonce, plaintext, associatedData)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

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

		corruptedCiphertext := make([]byte, len(ciphertext))
		copy(corruptedCiphertext, ciphertext)
		corruptedCiphertext[0] ^= 0x01

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
		timestamp, err := generateTimestamp()
		if err != nil {
			t.Fatalf("Failed to generate first timestamp: %v", err)
		}

		timestamp2, err := generateTimestamp()
		if err != nil {
			t.Fatalf("Failed to generate second timestamp: %v", err)
		}

		time1 := bytes.Compare(timestamp[:], timestamp2[:])
		if time1 > 0 {
			t.Error("second timestamp appears to be before first timestamp")
		}
	})

	t.Run("Timestamp validation", func(t *testing.T) {
		oldTimestamp := [12]byte{0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		newTimestamp := [12]byte{0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
		futureTimestamp := [12]byte{0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		if !validateTimestamp(newTimestamp, oldTimestamp) {
			t.Error("newer timestamp should be valid")
		}

		if validateTimestamp(oldTimestamp, newTimestamp) {
			t.Error("older timestamp should not be valid")
		}

		if validateTimestamp(newTimestamp, newTimestamp) {
			t.Error("identical timestamps should not be valid")
		}

		if !validateTimestamp(futureTimestamp, newTimestamp) {
			t.Error("future timestamp should be valid")
		}
	})
}
