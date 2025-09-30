# MiniWG: Educational WireGuard Implementation

A minimal, educational WireGuard implementation for learning cryptography and
networking protocols.

**Warning:** This is an educational implementation. Use official WireGuard for production.

## Overview

WireGuard is a modern VPN protocol that uses state-of-the-art cryptography.
This implementation focuses on clarity and learning rather than performance or
feature completeness.

![WireGuard High-Level Diagram](docs/ex/wg-diagram.png)

## Implementation Architecture

MiniWG implements the core WireGuard components with a focus on educational clarity:

![Implementation Components](docs/ex/implementation.png)

## Milestones Achieved

✅ **Milestone 1**: Two MiniWG peers communicate successfully
✅ **Milestone 2**: MiniWG interoperates with official WireGuard

## Features Implemented

- **Complete Noise_IK handshake protocol**
  - Ephemeral key generation and exchange
  - Static key authentication
  - Perfect forward secrecy
  - Replay protection with TAI64N timestamps

- **WireGuard-compatible cryptography**
  - ChaCha20Poly1305 AEAD encryption
  - BLAKE2s hashing and HMAC
  - Curve25519 elliptic curve operations
  - HKDF key derivation (KDF1, KDF2, KDF3)

- **Transport layer**
  - Packet encryption/decryption
  - Session management
  - Anti-replay protection

- **Event-driven architecture**
  - Concurrent TUN/UDP readers
  - Main event loop coordination
  - Proper shutdown handling

## Quick Start

TODO...

## Learning Resources

### Key Files for Study

- **`device/handshake.go`** - Complete Noise_IK handshake implementation
- **`device/crypto.go`** - Cryptographic primitives and key derivation
- **`device/transport.go`** - Packet encryption and session management
- **`device/loop.go`** - Event-driven architecture and coordination

### External References

- [WireGuard Whitepaper](docs/wireguard.pdf) - Original protocol specification
- [WireGuard-Go Implementation](https://github.com/WireGuard/wireguard-go) - Official reference implementation
- [Noise Protocol Framework](http://noiseprotocol.org/) - Cryptographic framework used by WireGuard

### Code Study Approach

TODO...

## Architecture Overview

MiniWG uses an event-driven architecture with separate goroutines for:

- **TUN Reader**: Captures outbound packets from the system
- **UDP Reader**: Receives WireGuard protocol messages
- **Main Loop**: Coordinates handshakes, encryption, and packet forwarding
- **Timer Manager**: Handles rekey and keepalive operations

The implementation separates concerns into distinct modules:
- Cryptographic operations (`crypto.go`)
- Protocol handshake logic (`handshake.go`)
- Transport layer encryption (`transport.go`)
- Network interfaces (`tun/`, `conn/`)

## Missing Features

This educational implementation focuses on core protocol understanding. Missing
features compared to production WireGuard include:

TODO...

## Acknowledgments

- [Jason](https://www.zx2c4.com) for writing such an incredible piece of software.
- [Noise Protocol Framework](http://noiseprotocol.org/) for the cryptographic foundation.
- [Jason](https://www.zx2c4.com) (and contributors) for the golang implementation.
