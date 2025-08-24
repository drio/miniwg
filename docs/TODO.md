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

