
# Tasks

## Crypto primitives (crypto.go)

- [x] **Curve25519 Operations**
  - [x] generateKeypair() - Generate Curve25519 private/public keypairs
  - [x] dhOperation() - Elliptic curve Diffie-Hellman key exchange

- [x] **BLAKE2s Hashing & MAC**
  - [x] blake2sHash() - BLAKE2s cryptographic hashing (32-byte output)
  - [x] blake2sMac() - BLAKE2s keyed MAC (16-byte output)
  - [x] blake2sHmac() - BLAKE2s HMAC (32-byte output)

- [x] **Key Derivation Functions (HKDF-based)**
  - [x] kdf1() - Single key derivation from chaining key + input
  - [x] kdf2() - Dual key derivation (chaining_key, encryption_key)
  - [x] kdf3() - Triple key derivation (chaining_key, temp_key, encryption_key)

- [x] **ChaCha20-Poly1305 AEAD**
  - [x] chachaPolyEncrypt() - Authenticated encryption with associated data
  - [x] chachaPolyDecrypt() - Authenticated decryption with associated data

- [x] **Timestamp Functions**
  - [x] generateTimestamp() - TAI64N timestamp generation
  - [x] validateTimestamp() - Replay attack prevention

##  4 Parts of WireGuard Handshake Protocol (handshake.go):

1. Create handshake initiation (initiator side)
    - [x]  Generate ephemeral keys, encrypt static key + timestamp

2. Process handshake initiation (responder side)
    - [x] Receive & validate the first message
    - [x] Decrypt static key, verify timestamp, derive shared state
    - [x] Sync the cryptographic ledger with initiator (ensure both sides have identical cryptographic state before proceeding.)

3. Create handshake response (responder side)
    - [x] Generate responder's ephemeral keys
    - [x] Encrypt empty payload, complete key derivation
    - [x] Send second message back

4. Process handshake response (initiator side)
    - [x] Receive & validate the second message
    - [x] Complete final key mixing, derive transport keys
    - [x] Both sides now have identical send/recv keys


> We now have a complete, working implementation of the WireGuard Noise_IK handshake protocol! 

The next logical steps would be:
- Transport data encryption/decryption (Tasks 5-6)
- Network interface integration (TUN/UDP - Tasks 10-11)
- Main event loop (Task 20)

## Understanding the handshake protocol and its purpose

The WireGuard handshake protocol's primary purpose is to securely establish
shared symmetric encryption keys that both parties can use for high-speed data
transmission. Starting with only knowledge of each other's static public keys,
the handshake uses the **Noise_IK** protocol to perform a cryptographic dance that
derives identical transport keys on both sides. 

This process provides mutual authentication (proving both parties are who they
claim to be): 

1. perfect forward secrecy (compromised long-term keys don't affect past sessions), 
2. key confirmation (both sides prove they derived the same keys),
3. replay protection (timestamps prevent reuse of old messages), 
4. and DoS protection (MAC system prevents resource exhaustion). 

The result is a secure, authenticated channel where the initiator's sending key
equals the responder's receiving key and vice versa, enabling fast
ChaCha20-Poly1305 encryption of tunnel traffic.

### Handshake Timeline: What Each Party Does

**Before handshake**: Both parties know each other's static public keys but have 
no shared secrets for encryption.

**Step 1 - Initiator Creates & Sends First Message (HandshakeInitiation)**

- Generates ephemeral keypair for this session
    We need that so we have a fresh set of keys per each handshake.
- Builds cryptographic ledger (chaining_key, hash) starting from protocol constants
    It is a running record of all the cryptographic operations performed during the handshake.
    It has two components:
        1. Chaining Key: accumulate crypotgraphic material.
        2. Hash: prevents tampering, we keep hashing as we add more operations.
    It is a way to confirm both sides did the same operations.
- Performs DH operations: ephemeral×peer_static, our_static×peer_static
    DH = Diffie-Hellman Key Exchange - a way for two parties to create a shared secret using 
    their public/private key pairs, even over an insecure channel.
- Encrypts our static public key (proves our identity to responder)
    The static public key is the public key that we generate with wg.
- Encrypts timestamp (prevents replay attacks)
    We encrypt (a the TAI64N timestamp.
    The encryption happens with AEAD (Authenticated encryption with associated data).
    Specifically we use: ChaCha20-Poly1305 
    - ChaCha20 gives confidentiality (hidden from network observers)
    - Poly1305 gives us authenticity (proves the encrypted data came with someone with the key).
    Associated data binding: The hash parameter gets authenticated but not encrypted. Ensures the
    timestamp is bound to a specific handshake context.
        In summary: Associated data binding ensures that encrypted data is not just
        authentic, but authentic in the right context.
- Calculates MAC1/MAC2 for DoS protection
    See (MAC for details). Wg uses the BLAKE2s MAC implementation.
    - MAC1 (Endpoint discovery protection)
        is computed with:  MAC(HASH(LABEL_MAC1 || peer_static_public), message_bytes)
        It just proves the sender knows the receiver public key. 
        Prevents from scanning ports to find wg instances.
        WG will drop the packet if it cannot validate the MAC1.
    - MAC2 (DoS protection)
        Only used under heavy load (othersize it is all zeros)
        If server detects load, switches to COOKIE MODE!
            Wireguard does not specify how to detect load. But there are different options.
            The canonical kernel implementation uses number of packets per second send by ip address.
        The server responds with: send me a cookie reply first.
        A legitimate client gets the cookie ands replies with a MAC2 that is valid
        An attacker won't be able to get the cookie. 
        NOTE: we don't need to implement this innitially in the first draft.
- Sends 148-byte message to responder

**Step 2 - Responder Receives & Processes First Message**

- Validates MAC1 (proves sender knows our static public key)
- Rebuilds identical cryptographic ledger by performing same operations
- Decrypts and validates initiator's static public key (authentication)
- Decrypts and validates timestamp (replay protection)
- Verifies cryptographic state matches initiator's
- Now both sides have synchronized chaining_key and hash

**Step 3 - Responder Creates & Sends Second Message (HandshakeResponse)**

- Generates responder's ephemeral keypair
- Continues cryptographic ledger with responder's ephemeral contribution
- Performs final DH operations: ephemeral×ephemeral, ephemeral×static
- Mixes pre-shared key (zeros in our implementation)
- Encrypts empty payload (proves successful key derivation)
- Calculates MAC1/MAC2 for DoS protection
- Sends 92-byte response to initiator

**Step 4 - Initiator Receives & Processes Second Message**

- Validates MAC1 (proves responder knows our static public key)
- Performs same final DH operations as responder
- Decrypts and validates empty payload (confirms responder derived same keys)
- Both sides now have identical final chaining_key

**Step 5 - Both Sides Derive Transport Keys**
- Initiator: derives sending_key, receiving_key from final chaining_key
- Responder: derives receiving_key, sending_key from same chaining_key (swapped)
- Key relationship: initiator.sending_key == responder.receiving_key
- **Handshake complete**: Both can now encrypt/decrypt data packets

### MACs

    (Wireguard uses the BLAKE2s MAC implementation.)
    MAC= Message authentication Code. Provides authenticity and integrity.
    MAC(key, message) → authentication_tag

      Core Properties:

      1. Authenticity:

      - Proves the message came from someone who has the key
      - Cannot be forged without the key

      2. Integrity:

      - Detects if the message was modified/corrupted
      - Any change to the message produces a different MAC

      3. Key-Dependent:

      - Same message + different key = different MAC
      - Without the key, you cannot create or verify MACs

    How MAC Works:

      Sender Side:

      message = "Hello Bob"
      key = "shared_secret_key"
      mac = MAC(key, message) // → "a1b2c3d4e5f6"

      // Send: message + mac
      send("Hello Bob" + "a1b2c3d4e5f6")

      Receiver Side:

      received_message = "Hello Bob"
      received_mac = "a1b2c3d4e5f6"

      // Compute expected MAC
      expected_mac = MAC(key, received_message)

      if expected_mac == received_mac {
          // ✅ Message is authentic and unmodified
      } else {
          // ❌ Either wrong sender or message was tampered with
      }




# NOTES and TODO


- [x] Add all crypto primitives
- [x] Handshake

* Phase 1: Message Foundation (messages.go)

  - [x] 1. Define message structs - HandshakeInitiation, HandshakeResponse, TransportData
  - [x] 2. Binary encoding/decoding - Marshal structs to bytes and back

* Phase 2: Handshake Steps (handshake.go)

- [ ] Create initiation - Generate ephemeral keys, encrypt static key + timestamp
- [ ] CProcess initiation - Decrypt, validate timestamp, derive shared state
- [ ] CCreate response - Generate ephemeral, encrypt empty payload
- [ ] CProcess response - Decrypt, complete handshake state

* Phase 3: Session Establishment

- [ ] Transport key derivation - Final step: chaining_key → send/recv keys
- [ ] Integration test - Two MiniWG instances complete full handshake

3. Routines to send read packets
4. Basic timer integration
5. Main event loopo
6. TUN/UDP interface integration
7. Simple testing.



### CIA

#### C - Confidentiality (what you called "encryption")

Ensures data is only readable by authorized parties
WireGuard achieves this through strong encryption algorithms

#### I - Integrity

Ensures data hasn't been tampered with or corrupted during transmission
WireGuard uses cryptographic hashing to detect any modifications to packets

#### A - Authentication

Verifies the identity of communicating parties
WireGuard uses public-key cryptography where each peer has a unique key pair

Using:

Confidentiality through ChaCha20 encryption
Integrity through Poly1305 authentication codes that detect tampering
Authentication through Curve25519 public keys that verify peer identities


### The whole data flow in practice:

Alice and Bob want to establish 

#### Step 1: Alice Creates Handshake Initiation

```go
  // Alice does:
  ephemeral_priv, ephemeral_pub := generateKeypair()  // Fresh keys for this session

  // Start the cryptographic ledger
  chaining_key := HASH("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
  hash := HASH(chaining_key + "WireGuard v1..." + bob_pub)

  // Mix ephemeral into the ledger
  chaining_key = kdf1(chaining_key, ephemeral_pub)
  hash = HASH(hash + ephemeral_pub)

  // Create shared secret with Bob's static key and encrypt Alice's identity
  shared1 := DH(ephemeral_priv, bob_pub)
  chaining_key, encrypt_key := kdf2(chaining_key, shared1)
  encrypted_static := AEAD(encrypt_key, 0, alice_pub, hash)

  // Encrypt timestamp to prevent replay
  shared2 := DH(alice_priv, bob_pub)
  chaining_key, encrypt_key := kdf2(chaining_key, shared2)
  encrypted_timestamp := AEAD(encrypt_key, 0, current_time(), hash)

  msg := HandshakeInitiation{
      Ephemeral: ephemeral_pub,
      Static: encrypted_static,      // Only Bob can decrypt this
      Timestamp: encrypted_timestamp // Prevents replay attacks
  }
  send_UDP(msg, bob_address)
```

#### Step 2: Bob Processes Initiation

Basically here Bob has to: 
1. Crypto ledger syncronization
2. Identity Authentication
   Purpose: Prove Alice is who she claims to be. 
   Only someone with Alice's private key could create a message that decrypts to her known public key.
3. Replay Attack Prevention
   timestamp := chachaPolyDecrypt(decrypt_key, 0, msg.Timestamp, hash)
   if validateTimestamp(timestamp, last_timestamp_from_alice) == false { reject }
   Purpose: Ensure this is a fresh handshake, not a replayed old message.
4. State Synchronization Verification 
    (syncing the cryptographic state with Alice so we are ready to continue with the next step in the protocol)
  After all operations, Bob has:
  - Same chaining_key as Alice ✓
  - Same hash state as Alice ✓
  - Verified Alice's identity ✓
  - Confirmed message freshness ✓

```go
  // Bob receives the message and does the SAME operations:
  chaining_key := HASH("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
  hash := HASH(chaining_key + "WireGuard v1..." + bob_pub)

  // Mix Alice's ephemeral (from message)
  chaining_key = kdf1(chaining_key, msg.Ephemeral)
  hash = HASH(hash + msg.Ephemeral)

  // Derive same shared secret and decrypt Alice's identity
  shared1 := DH(bob_priv, msg.Ephemeral)  // Same as Alice's shared1!
  chaining_key, decrypt_key := kdf2(chaining_key, shared1)
  alice_pub_decrypted := AEAD_decrypt(decrypt_key, 0, msg.Static, hash)

  // Verify Alice is who we expect
  if alice_pub_decrypted != alice_pub_we_know { reject }

  // Decrypt and validate timestamp
  shared2 := DH(bob_priv, alice_pub)  // Same as Alice's shared2!
  chaining_key, decrypt_key := kdf2(chaining_key, shared2)
  timestamp := AEAD_decrypt(decrypt_key, 0, msg.Timestamp, hash)

  if timestamp <= last_timestamp_from_alice { reject } // Replay protection

  // Bob now has the SAME chaining_key as Alice!
```

####  Step 3: Bob Creates Handshake Response

```go
  // Bob generates his ephemeral and completes the handshake
  bob_ephemeral_priv, bob_ephemeral_pub := generateKeypair()

  // Add Bob's ephemeral to the ledger
  chaining_key = kdf1(chaining_key, bob_ephemeral_pub)
  hash = HASH(hash + bob_ephemeral_pub)

  // Final key mixing - this creates the transport keys!
  shared3 := DH(bob_ephemeral_priv, msg.Ephemeral)  // Ephemeral-ephemeral
  chaining_key = kdf1(chaining_key, shared3)

  shared4 := DH(bob_ephemeral_priv, alice_pub)  // Bob's ephemeral + Alice's static
  chaining_key = kdf1(chaining_key, shared4)

  // Derive the final transport keys
  bob_send_key, bob_recv_key := kdf2(chaining_key, empty)

  response := HandshakeResponse{
      Ephemeral: bob_ephemeral_pub,
      Empty: AEAD(temp_key, 0, "", hash)  // Proves Bob can encrypt
  }
  send_UDP(response, alice_address)
```

#### Step 4: Alice Processes Response

```go
  // Alice does the same final mixing
  shared3 := DH(ephemeral_priv, msg.Ephemeral)  // Same as Bob's!
  shared4 := DH(alice_priv, msg.Ephemeral)      // Same as Bob's!
  // ... same chaining operations ...

  alice_send_key, alice_recv_key := kdf2(chaining_key, empty)

  // Key relationship:
  // alice_send_key == bob_recv_key  ✓
  // alice_recv_key == bob_send_key  ✓
```

####  Step 5: Send Encrypted Data

```go
  // Alice wants to send "Hello Bob!"
  plaintext := []byte("Hello Bob!")
  encrypted := chachaPolyEncrypt(alice_send_key, counter=0, plaintext, "")

  transport_msg := MarshalTransportData(bob_session_id, counter=0, encrypted)
  send_UDP(transport_msg, bob_address)

  // Bob receives and decrypts
  receiver, counter, ciphertext := UnmarshalTransportData(received_bytes)
  plaintext := chachaPolyDecrypt(bob_recv_key, counter, ciphertext, "")
  // plaintext == "Hello Bob!" ✓
```

Why This Works:

1. Both peers build identical ledgers - Each crypto operation is done by both sides
2. The chaining key accumulates all secrets - It contains contributions from both static keys, both ephemeral keys, and all DH
results
3. Transport keys are swapped - What Alice uses to send, Bob uses to receive
4. Perfect forward secrecy - Ephemeral keys are deleted after handshake

The beautiful part: After the handshake dance, both peers have the same final chaining_key, which they use to derive the same
transport encryption keys!



### The Flow with Key Derivation:

  1. Initiator: Create handshake initiation → send to responder
  2. Responder: Process handshake initiation → derive shared state
  3. Responder: Create handshake response → send to initiator
  4. Initiator: Process handshake response → derive shared state
  5. Both sides: Derive transport keys from final chaining key
  6. Both sides: Set hasSession = true, reset nonces to 0
  7. Transport: Now both can encrypt/decrypt data packets

The handshake creates two shared secrets - one for each direction of traffic:
Establish symmetric encryption keys for fast data transport.

The complex Noise_IK dance is just the secure way to get from static public
keys to shared transport encryption keys.


## Step 1-2: Main structs

Create main.go with core types:

```go
  type MiniWG struct {
      // Keys
      privateKey [32]byte
      publicKey  [32]byte
      peerKey    [32]byte

      // Session
      hasSession bool
      sendKey    [32]byte
      recvKey    [32]byte
      sendNonce  uint64
      localIndex uint32
      peerIndex  uint32

      // Network
      tun      *water.Interface
      udp      *net.UDPConn
      peerAddr *net.UDPAddr
  }
```

##  Step 3: TUN + UDP Setup

```go
  func (wg *MiniWG) initInterfaces() error {
      // Create TUN interface
      config := water.Config{DeviceType: water.TUN}
      config.Name = "miniwg0"
      wg.tun, _ = water.New(config)

      // Create UDP socket
      wg.udp, _ = net.ListenUDP("udp", &net.UDPAddr{Port: 51820})

      // Set peer endpoint (hardcoded for minimal version)
      wg.peerAddr, _ = net.ResolveUDPAddr("udp", "192.168.1.100:51820")

      return nil
  }
```

##  Step 4: Message Types

```go
  const (
      MessageInitiation = 1
      MessageResponse   = 2
      MessageData       = 4
  )

  type HandshakeInit struct {
      Type      uint32
      Sender    uint32
      Ephemeral [32]byte
      Static    [48]byte  // 32 + 16 auth tag
      Timestamp [28]byte  // 12 + 16 auth tag
      MAC1      [16]byte
      MAC2      [16]byte
  }
```

##  Step 5: Crypto Functions

```go
  func kdf1(key []byte, input []byte) []byte {
      hash, _ := blake2s.New256(key)
      hash.Write(input)
      return hash.Sum(nil)
  }

  func kdf2(key []byte, input []byte) ([]byte, []byte) {
      key1 := kdf1(key, append(input, 1))
      key2 := kdf1(key, append(input, 2))
      return key1, key2
  }

  func (wg *MiniWG) generateKeypair() {
      wg.privateKey = [32]byte(randomBytes(32))
      curve25519.ScalarBaseMult(&wg.publicKey, &wg.privateKey)
  }
```

##  Step 6: Handshake Creation

```go
  func (wg *MiniWG) createHandshakeInit() []byte {
      msg := HandshakeInit{
          Type:   MessageInitiation,
          Sender: wg.localIndex,
      }

      // Generate ephemeral keypair
      ephPriv := randomBytes(32)
      curve25519.ScalarBaseMult(&msg.Ephemeral, ephPriv)

      // Encrypt static key
      ss := curve25519.X25519(ephPriv, wg.peerKey[:])
      aead, _ := chacha20poly1305.New(kdf1(ss, nil))
      encrypted := aead.Seal(nil, make([]byte, 12), wg.publicKey[:], nil)
      copy(msg.Static[:], encrypted)

      return marshal(msg)
  }
```

##  Step 7: Main Event Loop

```go
  func (wg *MiniWG) run() {
      tunCh := make(chan []byte)
      udpCh := make(chan []byte)

      go wg.readTUN(tunCh)
      go wg.readUDP(udpCh)

      for {
          select {
          case packet := <-tunCh:
              wg.handleTUNPacket(packet)
          case packet := <-udpCh:
              wg.handleUDPPacket(packet)
          }
      }
  }
```

##  Step 8: Packet Handlers

```go
  func (wg *MiniWG) handleTUNPacket(packet []byte) {
      if !wg.hasSession {
          // Send handshake initiation
          hs := wg.createHandshakeInit()
          wg.udp.WriteToUDP(hs, wg.peerAddr)
          return
      }

      // Encrypt and send
      encrypted := wg.encryptPacket(packet)
      wg.udp.WriteToUDP(encrypted, wg.peerAddr)
  }

  func (wg *MiniWG) handleUDPPacket(packet []byte) {
      msgType := binary.LittleEndian.Uint32(packet[:4])
      switch msgType {
      case MessageInitiation:
          wg.processHandshakeInit(packet)
      case MessageResponse:
          wg.processHandshakeResponse(packet)
      case MessageData:
          wg.processDataPacket(packet)
      }
  }
```


### Layout

```
  miniwg/
  ├── main.go           # Main event loop
  ├── crypto.go         # Crypto functions
  ├── handshake.go      # Handshake protocol
  ├── transport.go      # Data encryption
  └── messages.go       # Wire format types
```

### Testing options


####  Option 1: Two Instances on Same Machine (Easiest for Development)

  # Terminal 1 - Instance A
  sudo ./miniwg -config=peer-a.conf
  # Creates tun interface: miniwg0 (10.0.0.1/24)
  # UDP listens on: 127.0.0.1:51820

  # Terminal 2 - Instance B
  sudo ./miniwg -config=peer-b.conf
  # Creates tun interface: miniwg1 (10.0.0.2/24)
  # UDP listens on: 127.0.0.1:51821
  # Connects to: 127.0.0.1:51820

  Test traffic:
  # From instance A, ping instance B
  ping 10.0.0.2  # Goes through encrypted tunnel via localhost UDP

####  Option 2: Two Physical/Virtual Machines (More Realistic)

  # Machine A (192.168.1.100)
  sudo ./miniwg
  # TUN: 10.0.0.1/24
  # UDP: 0.0.0.0:51820
  # Peer: 192.168.1.101:51820

  # Machine B (192.168.1.101)
  sudo ./miniwg
  # TUN: 10.0.0.2/24
  # UDP: 0.0.0.0:51820
  # Peer: 192.168.1.100:51820

####  Option 3: Test Against Real WireGuard (Ultimate Test)

  # Your minimal implementation
  sudo ./miniwg
  # TUN: 10.0.0.1/24

  # Real WireGuard on another machine
  sudo wg-quick up wg0
  # TUN: 10.0.0.2/24

  Recommended Development Flow

  Start with Option 1 (same machine):

  1. Easier debugging - Both instances in same environment
  2. No network setup - Uses localhost UDP
  3. Faster iteration - No need for multiple machines
  4. Packet capture - tcpdump -i lo port 51820 to see encrypted traffic

####   Configuration example for same-machine testing:

```go
  // Peer A config
  type Config struct {
      TUNName    string = "miniwg0"
      TUNIP      string = "10.0.0.1/24"
      UDPPort    int    = 51820
      PeerIP     string = "127.0.0.1"
      PeerPort   int    = 51821
  }

  // Peer B config
  type Config struct {
      TUNName    string = "miniwg1"
      TUNIP      string = "10.0.0.2/24"
      UDPPort    int    = 51821
      PeerIP     string = "127.0.0.1"
      PeerPort   int    = 51820
  }
```

  Traffic flow on same machine:
  App: ping 10.0.0.2
    ↓
  Kernel: Route via miniwg0
    ↓
  Your WireGuard A: Encrypt packet
    ↓
  UDP: Send to 127.0.0.1:51821
    ↓
  Your WireGuard B: Decrypt packet
    ↓
  Kernel: Inject into miniwg1
    ↓
  App: Receive ping on 10.0.0.2

  This gives you a complete encrypted tunnel running entirely on localhost - perfect for development and
  learning!

