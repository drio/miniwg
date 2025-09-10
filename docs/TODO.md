
# Tasks

##  4 Parts of WireGuard Handshake Protocol:

1. Create handshake initiation (initiator side)
    - [x]  Generate ephemeral keys, encrypt static key + timestamp

2. Process handshake initiation (responder side)
    - Receive & validate the first message
    - Decrypt static key, verify timestamp, derive shared state
    - Sync the cryptographic ledger with initiator (ensure both sides have identical cryptographic state before proceeding.)

3. Create handshake response (responder side)
    - Generate responder's ephemeral keys
    - Encrypt empty payload, complete key derivation
    - Send second message back

4. Process handshake response (initiator side)
    - Receive & validate the second message
    - Complete final key mixing, derive transport keys
    - Both sides now have identical send/recv keys


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

