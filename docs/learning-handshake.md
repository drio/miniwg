# Understanding the WireGuard Handshake

## 0. Cryptography Vocabulary - The Building Blocks

Before diving into the handshake, let's define the core cryptographic terms
you'll encounter:

### Security Properties

**Authentication**
Proving identity - confirming that a party is who they claim to be.
Example: Alice proves she has the private key matching her public key.

**Encryption**
Transforming plaintext into ciphertext so only authorized parties can read it.
Example: Converting "Hello" → "8x!2aQ" using a secret key.

**Confidentiality**
Ensuring data can only be read by intended recipients (achieved via
encryption).
Example: Your message is encrypted so eavesdroppers can't read it.

**Integrity**
Ensuring data hasn't been modified or tampered with.
Example: Detecting if "Transfer $10" was changed to "Transfer $1000".

**Forward Secrecy**
Past sessions remain secure even if long-term keys are compromised later.
Example: If your private key leaks today, yesterday's encrypted messages
remain unreadable.

**Replay Protection**
Preventing attackers from capturing and re-sending valid messages.
Example: Stopping someone from recording "unlock door" and replaying it
later.

### Cryptographic Building Blocks

**Symmetric Key**
Same key used for encryption and decryption. Fast but requires secure key
sharing.
Example: AES, ChaCha20 - both parties must have the same secret key.

**Asymmetric Key (Public Key Cryptography)**
Key pair: public key (shareable) and private key (secret).
Example: Curve25519 - encrypt with public key, decrypt with private key.

**Hash Function**
One-way function that produces fixed-size output (digest) from any input.
Properties: deterministic, irreversible, collision-resistant.
Example: BLAKE2s - same input always gives same hash, can't reverse it.

**MAC (Message Authentication Code)**
A tag that proves message authenticity and integrity using a shared secret.
Example: HMAC - verifies message came from someone who knows the secret key.

**AEAD (Authenticated Encryption with Associated Data)**
Combines encryption + authentication in one operation.
Example: ChaCha20-Poly1305 - encrypts data AND proves it hasn't been
tampered with.

**KDF (Key Derivation Function)**
Transforms secret material into one or more cryptographic keys.
Example: HKDF - takes DH result and derives separate encryption keys.

**DH (Diffie-Hellman Key Exchange)**
Protocol for two parties to agree on a shared secret over public channel.
Example: Alice and Bob derive same secret without ever sending it.

**Nonce (Number Used Once)**
A value that must never repeat with the same key. Ensures uniqueness.
Example: Counter incremented for each message: 0, 1, 2, 3...

### WireGuard-Specific Terms

**Ephemeral Key**
Temporary key used for one session, then deleted (provides forward secrecy).
Example: Generated fresh for each handshake, never stored.

**Static Key**
Long-term key that identifies a peer (like your identity).
Example: Your WireGuard private/public key pair in the config.

**Session Key / Transport Key**
Short-lived keys derived from handshake, used to encrypt data packets.
Example: After handshake completes, these encrypt your actual traffic.

**Chaining Key**
Running accumulator of all secrets during handshake (internal state).
Example: Continuously updated as each DH operation adds new secret material.

**Hash Transcript**
Running hash of all messages exchanged (tamper-evident log).
Example: Records every public key and ciphertext sent/received.

**Initiator**
The peer who starts the handshake (sends message 1).

**Responder**
The peer who receives the handshake and responds (sends message 2).

### Key Insight

These terms build on each other. Understanding each individually makes the
full handshake comprehensible:

```
DH creates shared secret
  ↓
KDF derives keys from secret
  ↓
AEAD encrypts with derived keys
  ↓
Hash transcript proves no tampering
  ↓
Result: Authenticated, encrypted, forward-secret session
```

---

## 1. Start with the "Why" - The Security Goals

Before diving into crypto, understand what the handshake must achieve:

**Ask yourself**: What would a "perfect" handshake do? <br/>
- ✅ Prove both parties are who they claim (authentication) <br/>
- ✅ Derive a shared secret only they know (key agreement) <br/>
- ✅ Protect past sessions if keys leak later (forward secrecy) <br/>
- ✅ Hide who's talking to whom (identity hiding) <br/>
- ✅ Prevent replay attacks (freshness) <br/>
- ✅ Be fast and simple

**Exercise**: Write down these goals. For each line of handshake code,
ask "which goal does this serve?"

### Mapping Goals to Code

As you read the handshake, annotate which goal each step serves:

```
Generate ephemeral keypair          → Forward secrecy
DH(ephemeral × static)             → Key agreement + Identity hiding
DH(static × static)                → Authentication
Encrypt static key                 → Identity hiding
Encrypt timestamp                  → Freshness / Replay protection
MAC1                              → DoS protection
```

**Key insight**: Every operation serves at least one security goal.
Nothing is arbitrary.

---

## 2. Understanding Diffie-Hellman (DH)

### The Magic Trick

**Goal**: Alice and Bob want a shared secret, but only talk over public
channel

**The Math Property (Curve25519)**:
```
Alice: private_A × BasePoint = public_A
Bob:   private_B × BasePoint = public_B

Alice computes: private_A × public_B = shared_secret
Bob computes:   private_B × public_A = shared_secret

SAME SECRET! (because × is commutative)
```

**Eavesdropper sees**: public_A, public_B (can't compute shared_secret
without private keys)

### Exercise: Trace One DH Operation

From handshake.go:86-89:
```go
dhResult1, err := dhOperation(state.ephemeralPrivate,
                               state.peerStaticPublic)
```

**What this does**:
- Input: My ephemeral private key × Peer's static public key
- Output: Shared secret only I and peer can compute
- Peer will compute: Their static private × My ephemeral public
  = SAME secret

**Why it matters**: This shared secret becomes an encryption key

### Practice

1. Generate two keypairs (use crypto.go:GenerateKeypair)
2. Compute DH from both sides
3. Verify you get the same result
4. Try with wrong private key - different result!

### Key Insight

DH doesn't encrypt anything. It just creates a shared secret between two
parties who each have one private key and one public key.

---

## 3. Understanding AEAD (Authenticated Encryption)

### What It Does

**AEAD = Authenticated Encryption with Associated Data**

Three operations in one:

1. **Encrypt** plaintext → ciphertext
2. **Authenticate** ciphertext (detect tampering)
3. **Authenticate** additional data (without encrypting it)

### WireGuard Uses ChaCha20-Poly1305

```go
ciphertext = AEAD_Encrypt(key, nonce, plaintext, additionalData)
// Returns: encrypted_plaintext || 16_byte_auth_tag
```

**Decryption**:
```go
plaintext = AEAD_Decrypt(key, nonce, ciphertext, additionalData)
// If auth tag doesn't match → ERROR (tampering detected!)
```

### The Critical Rule: NEVER Reuse (key, nonce)

```
✅ GOOD:
encrypt(key, nonce=0, msg1)
encrypt(key, nonce=1, msg2)  // Different nonce

❌ CATASTROPHIC:
encrypt(key, nonce=0, msg1)
encrypt(key, nonce=0, msg2)  // Same (key, nonce) → Security broken!
```

### Why Handshake Can Use nonce=0

Each encryption key in the handshake is **single-use**:
```go
// Step 7: Encrypt static key
encryptedStatic = AEAD(tempKey1, nonce=0, ourStaticPub, hash)
// tempKey1 is NEVER used again!

// Step 10: Encrypt timestamp
encryptedTimestamp = AEAD(tempKey2, nonce=0, timestamp, hash)
// tempKey2 is NEVER used again!
```

Each key used exactly once → safe to use nonce=0

### What is "Additional Data"?

Data that's **authenticated but NOT encrypted**:

```go
encryptedStatic = AEAD(key, nonce=0, ourStaticPub, hash)
//                                    ^^^^^^^^^^^^  ^^^^
//                                    encrypted     authenticated (not encrypted)
```

**Why?** Binds encryption to context. If someone tampers with the hash (the transcript), decryption fails.

### Exercise: Trace One Encryption

From handshake.go:103:
```go
encryptedStatic = chachaPolyEncrypt(state.tempKey1, 0,
                                    state.ourStaticPublic[:],
                                    state.hash[:])
```

**What happens**:

1. Encrypt `ourStaticPublic` (32 bytes) with `tempKey1`
2. Compute auth tag over: encrypted data + hash (additional data)
3. Return: 32 encrypted bytes + 16 byte tag = 48 bytes total

**Responder will**:

1. Use same key (from same DH operation)
2. Decrypt with same hash as additional data
3. If hash is wrong → auth tag mismatch → handshake fails

### Key Insight

AEAD is the "lock and seal" - it encrypts AND proves no tampering.
The additional data is the "envelope" - authenticated but readable context.

---

## 4. Understanding KDF (Key Derivation Function)

### The Problem KDFs Solve

**Never use raw secrets directly**:
```go
sharedSecret = DH(myPrivate, theirPublic)
encryptionKey = sharedSecret  // ❌ BAD!
```

**Why bad?**
- DH output has structure (not uniformly random)
- No domain separation (can't derive multiple keys safely)
- Single point of failure

### HKDF Pattern: Extract-then-Expand

**Extract** (strengthen):
```go
strongKey = HMAC(salt, inputMaterial)
```

**Expand** (stretch):
```go
output1 = HMAC(strongKey, 0x1)
output2 = HMAC(strongKey, output1 || 0x2)
output3 = HMAC(strongKey, output2 || 0x3)
```

The counters (0x1, 0x2, 0x3) provide **domain separation** - makes each output cryptographically independent.

### Three KDFs in WireGuard

**kdf1** - One output:
```go
newChainingKey = kdf1(chainingKey, newData)
// Updates the chain with new data
```

**kdf2** - Two outputs:
```go
newChainingKey, encryptionKey = kdf2(chainingKey, dhResult)
// 1. Continue the chain
// 2. Derive encryption key for immediate use
```

**kdf3** - Three outputs:
```go
newChainingKey, tau, encryptionKey = kdf3(chainingKey, presharedKey)
// 1. Continue the chain
// 2. tau (mixed into hash)
// 3. Encryption key
```

### The Chaining Key Concept

Think of it as a **cryptographic ledger**:

```
Start:    chainingKey = InitialChainKey
Step 1:   chainingKey = kdf1(chainingKey, ephemeral)       // Added ephemeral
Step 2:   chainingKey = kdf2(chainingKey, DH1)             // Added DH1 secret
Step 3:   chainingKey = kdf2(chainingKey, DH2)             // Added DH2 secret
...
Final:    chainingKey contains ALL secrets mixed together
```

**Final transport keys derived from this complete chain**:
```go
sendKey, recvKey = kdf2(finalChainingKey, nil)
```

### Exercise: Trace KDF Usage

From handshake.go:94-98:
```go
newChainingKey2, encryptKey1, err := kdf2(state.chainingKey[:],
                                           dhResult1[:])
state.chainingKey = newChainingKey2
state.tempKey1 = encryptKey1
```

**What happens**:

1. Input: Current chainingKey + DH shared secret
2. Extract: Mix them with HMAC
3. Expand: Derive two independent keys
4. Output 1: New chainingKey (continues the chain)
5. Output 2: Encryption key (used once to encrypt static key)

**Why two outputs?**

- Need to continue accumulating secrets (chainingKey)
- Need encryption key for this step (tempKey1)

### Key Insight

KDF is the "key factory" - turns raw secrets into proper encryption keys.
The chaining key is a running total of all secrets accumulated during the
handshake.

---

## 5. The Hash Transcript

### What It Is

A **running hash of all messages** exchanged:

```go
hash = InitialHash
hash = HASH(hash || peer_static_public)
hash = HASH(hash || ephemeral_public)
hash = HASH(hash || encrypted_static)
hash = HASH(hash || encrypted_timestamp)
// ... keeps recording
```

### Why Different from Chaining Key?

| Hash Transcript | Chaining Key |
|-----------------|--------------|
| Records **what was sent** | Records **secrets shared** |
| Public + encrypted data | Only secret data (DH results) |
| Used for **authentication** | Used for **key derivation** |
| Used as AEAD additional data | Used to derive encryption keys |

### Purpose: Prevent Tampering

Used as **additional data in AEAD**:
```go
encrypted = AEAD(key, nonce, plaintext, hash)
//                                      ^^^^
//                                      Current transcript state
```

If attacker modifies earlier messages → hash changes → AEAD decryption fails

### Exercise: Trace Hash Updates

From handshake.go:
```go
Line 62:  mixHash(&state.hash, &state.hash, peerStaticPub[:])
Line 77:  mixHash(&state.hash, &state.hash, state.ephemeralPublic[:])
Line 114: mixHash(&state.hash, &state.hash, state.encryptedStatic[:])
Line 150: mixHash(&state.hash, &state.hash, state.encryptedTimestamp[:])
```

**Pattern**: After every significant event, update the transcript

**Result**: Final hash = cryptographic summary of entire conversation

### Key Insight

The hash is a **tamper-evident log**. Both parties maintain identical logs.
Any divergence → handshake fails.

---

## 6. Putting It Together: The Handshake Flow

### Step-by-Step Mental Model

**Think of the handshake as building a house**:

1. **Foundation** (Initialize):
   - Both start with same foundation (InitialChainKey, InitialHash)

2. **Frame** (Message 1 - DH operations 1 & 2):
   - Initiator generates ephemeral key (temporary support beam)
   - DH #1: Create first shared secret → encrypt identity
   - DH #2: Create second shared secret → prove authentication

3. **Roof** (Message 2 - DH operations 3 & 4):
   - Responder generates ephemeral key (complete the frame)
   - DH #3: Ephemeral-ephemeral → forward secrecy
     (can tear down temporary beams later)
   - DH #4: Final binding → lock everything together

4. **Move In** (Derive Transport Keys):
   - House complete, derive final keys from accumulated secrets
   - Start encrypting data

### The Four DH Operations

Each DH serves a specific purpose:

```
DH #1: ephemeral_i × static_r
→ Purpose: Encrypt initiator's identity
  (only responder can decrypt)

DH #2: static_i × static_r
→ Purpose: Mutual authentication
  (prove both have private keys)

DH #3: ephemeral_i × ephemeral_r
→ Purpose: Forward secrecy
  (ephemeral keys deleted after handshake)

DH #4: static_i × ephemeral_r
→ Purpose: Bind responder's ephemeral to initiator's identity
```

All four DH results → mixed into chainingKey → derive transport keys

### Message Flow

```
Initiator                           Responder
---------                           ---------

1. Generate ephemeral
2. DH #1 (eph × peer_static)
3. Encrypt my static key
4. DH #2 (static × peer_static)
5. Encrypt timestamp
6. Send message 1 ───────────────→

                                    7. Receive message 1
                                    8. Validate MAC1
                                    9. DH #1
                                       (static × initiator_eph)
                                    10. Decrypt initiator static
                                    11. DH #2
                                        (static × initiator_static)
                                    12. Decrypt timestamp
                                    13. Validate timestamp

                                    14. Generate ephemeral
                                    15. DH #3
                                        (eph × initiator_eph)
                                    16. DH #4
                                        (eph × initiator_static)
                                    17. Mix PSK
                                    18. Encrypt empty
                                    19. Send message 2 ←──────────────

20. Receive message 2
21. Validate MAC1
22. DH #3
    (eph × responder_eph)
23. DH #4
    (static × responder_eph)
24. Mix PSK
25. Decrypt empty
26. Validate

Both now have identical chainingKey
Both derive: sendKey, recvKey = kdf2(chainingKey, nil)
Initiator uses: send=key1, recv=key2
Responder uses: send=key2, recv=key1  (swapped!)

Session established ✓
```

### Key Insight

The handshake is a carefully choreographed dance where both parties:

1. Perform same crypto operations (staying in sync)
2. Accumulate secrets into chainingKey (building up entropy)
3. Maintain hash transcript (tamper-evident log)
4. Arrive at identical state (synchronized)
5. Derive transport keys (ready to encrypt data)

---

## 7. Handshake in Detail - Step by Step

This section walks through each of the four handshake functions, showing
exactly what happens at each step with actual variable names from the code.

### Part 1/4: CreateMessageInitiation()

The initiator creates the first handshake message. This function performs
2 DH operations and encrypts the initiator's identity.

---

**INITIALIZATION - Start with protocol constants**

**Step 1:** Initialize state (set state.chainingKey and state.hash)<br/>

---

**BIND TO PEER - Record who we're talking to**

**Step 2:** Mix peerStaticPub into state.hash<br/>

---

**EPHEMERAL SETUP - Create temporary keys for forward secrecy**

**Step 3:** Generate state.ephemeralPrivate, state.ephemeralPublic<br/>
**Step 4:** Mix state.ephemeralPublic into state.hash<br/>
**Step 5:** Mix state.ephemeralPublic into state.chainingKey via kdf1<br/>

---

**DH #1 - Hide initiator identity (only responder can decrypt)**

**Step 6:** DH #1: dhOperation(state.ephemeralPrivate,
state.peerStaticPublic) → dhResult1<br/>
**Step 7:** kdf2(state.chainingKey, dhResult1) → state.chainingKey,
state.tempKey1<br/>
**Step 8:** Encrypt state.ourStaticPublic with state.tempKey1 →
state.encryptedStatic<br/>
**Step 9:** Mix state.encryptedStatic into state.hash<br/>

---

**DH #2 - Mutual authentication + replay protection**

**Step 10:** DH #2: dhOperation(state.ourStaticPrivate,
state.peerStaticPublic) → dhResult2<br/>
**Step 11:** kdf2(state.chainingKey, dhResult2) → state.chainingKey,
state.tempKey2<br/>
**Step 12:** Generate timestamp<br/>
**Step 13:** Encrypt timestamp with state.tempKey2 →
state.encryptedTimestamp<br/>
**Step 14:** Mix state.encryptedTimestamp into state.hash<br/>

---

**FINALIZE - Package and protect message**

**Step 15:** Marshal message (HandshakeInitiation)<br/>
**Step 16:** Compute MAC1 (DoS protection - prove we know peer's key)<br/>
**Step 17:** MAC2 set to zero (normal case - no cookie yet)<br/>
**Step 18:** Return message + state<br/>

---

**Key Observations:**

- **Chaining key grows** like a snowball: Initial → +ephemeral → +DH1 →
  +DH2
- **Hash transcript** records everything: peer key, ephemeral, encrypted
  payloads
- **Two temp keys** (tempKey1, tempKey2) used once each, then discarded
- **State saved** for processing the response (contains chainingKey, hash,
  ephemeral keys)

**What gets sent to responder:**

- Sender index (our chosen ID)
- Ephemeral public key (plaintext)
- Encrypted static public key (48 bytes: 32 data + 16 auth tag)
- Encrypted timestamp (28 bytes: 12 data + 16 auth tag)
- MAC1 (16 bytes)
- MAC2 (16 bytes, all zeros)

Total: 148 bytes

---

## 8. Learning Strategy

### Build Understanding Incrementally

**Week 1: Primitives**
- Study DH in isolation (crypto.go:28-50)
- Study AEAD in isolation (crypto.go:201-238)
- Study KDF in isolation (crypto.go:113-193)
- **Don't** try to understand the full handshake yet

**Week 2: Simple Flows**
- Trace ONE DH operation through both sides
- Trace ONE encryption/decryption through both sides
- Trace how chainingKey updates through one KDF call

**Week 3: First Half of Handshake**
- Study CreateMessageInitiation (initiator side)
- Study ConsumeMessageInitiation (responder side)
- Focus on: "How does responder sync state?"

**Week 4: Second Half**
- Study CreateMessageResponse (responder side)
- Study ConsumeMessageResponse (initiator side)
- Focus on: "How do transport keys get derived?"

### Active Learning Exercises

1. **Draw it**: Sketch the message flow on paper
2. **Trace it**: Use a debugger, step through one handshake
3. **Break it**: Remove one DH - what security property breaks?
4. **Modify it**: Change one hash input - where does it fail?
5. **Teach it**: Explain to rubber duck/friend without looking at code

### Debug Commands

```bash
# Run tests with verbose output
go test -v ./device -run TestHandshake

# Run with race detector
go test -race ./device

# Step through with delve debugger
dlv test ./device -- -test.run TestHandshake
```

### When You're Stuck

Ask yourself:

1. **Which security goal does this serve?** (auth, key agreement, forward secrecy, etc.)
2. **What would an attacker do if we removed this?**
3. **How does this contribute to the final transport keys?**
4. **Is this creating a secret or authenticating data?**

### Reference Materials

- WireGuard paper: `docs/wireguard.pdf`
- Noise Protocol spec: https://noiseprotocol.org/noise.html
- Your flashcards: `claude/anki.basics.txt`, `claude/anki.syncstate.txt`
- Official implementation: `~/dev/github.com/Wireguard/wireguard-go`

---

## 8. Common Mental Blocks and How to Overcome Them

### "Too Many DH Operations!"

**Simplify**: Group them by purpose
- DH #1 & #2: Message 1 (initiator proves identity)
- DH #3 & #4: Message 2 (responder completes handshake)

**Remember**: Each DH creates ONE shared secret. Four DH = four secrets. All four go into chainingKey.

### "Why So Many Keys?"

We generate many keys during the handshake but only use two (sendKey,
recvKey) for transport. Here's why:

**Keys generated during handshake:**

1. **Ephemeral private/public keys** (2 pairs - one per peer)
   - Purpose: Forward secrecy
   - Used for: DH operations, then DELETED after handshake
   - Why: If your static key leaks later, past sessions remain secure

2. **tempKey1** (first encryption key)
   - Purpose: Encrypt initiator's static public key in Message 1
   - Source: Derived from `kdf2(chainingKey, DH_result_1)`
   - Why: Single-use key for encrypting identity (identity hiding)
   - Used once, then discarded

3. **tempKey2** (second encryption key)
   - Purpose: Encrypt timestamp in Message 1
   - Source: Derived from `kdf2(chainingKey, DH_result_2)`
   - Why: Single-use key for encrypting timestamp (freshness)
   - Used once, then discarded

4. **tempKey3** (third encryption key, in Message 2)
   - Purpose: Encrypt empty payload in Message 2 (or with PSK)
   - Source: Derived from `kdf3(chainingKey, psk)` if PSK present
   - Why: Proves responder completed handshake correctly
   - Used once, then discarded

5. **Transport keys** (sendKey, recvKey)
   - Purpose: Encrypt actual data packets after handshake
   - Source: Final `kdf2(chainingKey, nil)` using ALL accumulated secrets
   - Why: These are the only keys that persist and encrypt your traffic

**Why so many temporary keys?**

Each step in the handshake encrypts different data with a **fresh,
single-use key**:

- Prevents key reuse attacks
- Each encryption has independent security
- If one step fails, doesn't compromise others
- Follows Noise protocol's key ratcheting pattern

**The pattern:**

```
DH operation → derive tempKey → encrypt one thing → discard tempKey → repeat
```

**Think of it like this:**

- Temporary keys = scaffolding while building a house (removed after)
- Transport keys = the actual house you live in

The many temporary keys are part of the **key derivation chain** - each
adds security properties (authentication, identity hiding, freshness) but
we only keep the final transport keys because they contain all the
accumulated entropy from every DH operation.

**Summary in layers:**

- **Ephemeral keys**: Temporary (forward secrecy)
- **Static keys**: Permanent (authentication)
- **Temporary encryption keys** (tempKey1, tempKey2, tempKey3):
  Single-use (from DH results)
- **Transport keys**: Final (from complete chainingKey)

**Each layer serves a purpose**. Draw boxes and arrows to visualize.

### "Hash vs ChainingKey Confusion"

**Use this table**:

| Question | Hash | ChainingKey |
|----------|------|-------------|
| What goes in? | All data (public + encrypted) | Only secrets (DH results) |
| Where is it used? | AEAD additional data | KDF input |
| What's it for? | Authentication / tamper detection | Key derivation |
| Does it contain secrets? | No (public log) | Yes (accumulated secrets) |

### "State Synchronization Is Confusing"

**Key realization**:
- Both parties do **same operations**
- But from **different perspectives** (Alice uses her private key, Bob uses his)
- DH is **commutative** so they get **same shared secrets**
- Result: **identical hash and chainingKey**

**Test it**: Run handshake in debugger, pause at end of each function, compare initiator and responder values.

---

## 9. Final Mental Model

The handshake is like two people building the same LEGO model:

1. **Same instructions** (Noise_IK protocol)
2. **Different pieces** (different private keys)
3. **Trade pieces** (exchange public keys/messages)
4. **Build together** (DH operations create shared secrets)
5. **Same result** (identical chainingKey and hash)
6. **Use the model** (derive transport keys, encrypt data)

If at any step the models don't match → handshake fails.

**The beauty**: Even though they start with different secrets (private keys),
they arrive at the same shared state through carefully designed crypto
operations.

---

## You've Got This!

The handshake seems overwhelming because it combines multiple primitives
in a specific sequence. But each piece is understandable on its own.

**Start small. Build up. Connect the dots.**

Take breaks. It took the cryptographers years to design this. It's OK if
it takes you weeks to fully understand it.

The fact that you're asking "why do we use these primitives?" shows you're
thinking deeply. Keep that curiosity. It will lead to true understanding.

---

## 10. Noise Protocol Framework - The IK Pattern

### What is Noise?

Noise is a **framework for building crypto protocols**. Instead of inventing
handshakes from scratch, you pick a proven pattern.

Think of it like LEGO instructions - different patterns for different needs.

### WireGuard Uses Noise_IKpsk2

**IKpsk2 = Identity + Known + Pre-Shared Key (mixed at stage 2)**

- **I (Identity)**: Initiator sends their static key (encrypted)
- **K (Known)**: Responder's static key is known in advance
- **psk2**: Pre-shared key mixed in after the second DH operation

**Why IKpsk2?**

- Initiator must know responder's public key before starting
- Provides identity hiding (initiator's identity is encrypted)
- One round-trip handshake (fast!)
- Mutual authentication
- Optional PSK for post-quantum security

### Other Noise Patterns (for context)

**XX**: Neither party knows the other's key
- More flexible, but 1.5 round trips
- Used by: Signal protocol

**NK**: Only responder sends identity
- One-way authentication
- Used when server authenticates to client, but not vice versa

**IKpsk2 (WireGuard's choice)**:

- Both authenticate
- Fast (1 round trip)
- Initiator identity hidden from passive observers
- PSK optional (degrades to plain IK when not configured)

### The IKpsk2 Message Pattern

```
→ e, es, s, ss
← e, ee, se, psk
```

**Message 1 (initiator → responder)**:

- `e`: Send ephemeral public key
- `es`: DH(ephemeral_i, static_r) - mix into key
- `s`: Send static public key (encrypted with key from `es`)
- `ss`: DH(static_i, static_r) - mix into key

**Message 2 (responder → initiator)**:

- `e`: Send ephemeral public key
- `ee`: DH(ephemeral_i, ephemeral_r) - mix into key
- `se`: DH(static_i, ephemeral_r) - mix into key
- `psk`: Mix pre-shared key (if configured)

This notation directly maps to the 4 DH operations + PSK mixing in
WireGuard!

### What Noise Guarantees

The Noise Protocol Framework provides **cryptographic recipes that are known
to work** - each pattern has been **formally verified** using cryptographic
proofs and automated verification tools.

**What Noise provides:**

1. **Proven patterns** - Mathematical proofs that patterns provide claimed
   security properties (authentication, confidentiality, forward secrecy)

2. **Known security properties** - Each pattern comes with documented
   security profile: what it protects against, what guarantees it provides

3. **Implementation guidance** - Precise specification of how to implement
   each pattern correctly (order of operations, when to mix keys, etc.)

**Noise patterns are proven secure IF:**

- ✅ You implement them correctly (no bugs)
- ✅ Underlying primitives are secure (Curve25519, ChaCha20-Poly1305,
  BLAKE2s)
- ✅ You don't deviate from the pattern
- ✅ You handle surrounding protocol correctly (transport, replay
  protection, etc.)

**Noise gives you:**

- ✅ A proven recipe that's cryptographically sound
- ✅ Protection from common protocol design mistakes
- ✅ Formal verification that the pattern works as claimed

**Noise doesn't protect you from:**

- ❌ Implementation bugs (buffer overflows, timing attacks, etc.)
- ❌ Side-channel attacks (if you implement crypto primitives poorly)
- ❌ Issues outside the handshake (like weak replay protection)

**Think of it like a recipe from a Michelin-star chef** - the recipe is
proven to work, but you still need to execute it correctly in your kitchen.

### Key Insight

Noise_IKpsk2 gives WireGuard its security properties for free. Understanding
IKpsk2 helps you see why the handshake is structured this way - it's
following a proven, formally verified pattern. The hard cryptographic work
has been done and verified - WireGuard just needs to implement it correctly.

---

## 11. MAC1 and MAC2 - DoS Protection

### The Problem: Handshake Amplification Attacks

**Attack scenario**:

1. Attacker spoofs victim's IP address
2. Sends handshake initiation to WireGuard server
3. Server does expensive crypto (DH operations)
4. Server sends large response to victim
5. Attacker repeats with minimal cost

Result: **DDoS amplification** - attacker uses server to flood victim

### The Solution: Cookie-Reply Mechanism

**MAC1**: Always present, proves sender knows responder's public key
**MAC2**: Optional, proves sender recently received a cookie

### How It Works

**Normal case (no attack)**:
```
Initiator → Responder: Handshake with MAC1 (MAC2 empty)
Responder: Validates MAC1, processes handshake
```

**Under load (potential attack)**:
```
Initiator → Responder: Handshake with MAC1 (MAC2 empty)
Responder: Validates MAC1, but system is under load
Responder → Initiator: Cookie-reply message (NOT handshake response)
Initiator: Stores cookie
Initiator → Responder: Handshake with MAC1 + MAC2 (includes cookie)
Responder: Validates MAC2, processes handshake
```

### MAC1 Computation

```go
mac1Key = HASH("mac1----" || responderPublicKey)
mac1 = MAC(mac1Key, entireMessage[0:116])
```

**Purpose**: Proves sender knows responder's public key. Prevents random
garbage packets from consuming CPU.

### MAC2 Computation

```go
// Responder sends cookie encrypted with sender's IP
cookie = AEAD_Encrypt(cookieKey, nonce, randomBytes, senderIP)

// Initiator uses cookie for MAC2
mac2 = MAC(cookie, entireMessage[0:116])
```

**Purpose**: Proves sender received a cookie from this server recently.
IP address is bound to cookie, so attacker can't use victim's IP.

### When is MAC2 Required?

- Responder tracks load (packets per second)
- If load exceeds threshold → require MAC2
- If initiator sends without MAC2 → send cookie-reply
- If initiator sends with valid MAC2 → process handshake

### Key Insight

MAC1/MAC2 create a stateless cookie system. Server doesn't store state
until handshake is validated. This prevents resource exhaustion attacks
while allowing legitimate peers to connect quickly.

---

## 12. Pre-Shared Key (PSK) - Post-Quantum Security

### What is PSK?

An **optional shared secret** both peers know in advance (like a password).
Mixed into the handshake for additional security.

### Why Use PSK?

**Post-quantum security**: If quantum computers break Curve25519 in the
future, past traffic remains secure because PSK (shared via different
channel) adds entropy that quantum computers can't recover.

**Defense in depth**: Even if DH is compromised, PSK provides protection.

### How PSK is Used in Handshake

From the code (handshake.go):
```go
// After DH operations, mix in PSK
if presharedKey is set {
    chainingKey, tau, tempKey = kdf3(chainingKey, presharedKey)
    hash = HASH(hash || tau)
}
```

**Step by step**:

1. Complete all DH operations first
2. Use kdf3 to mix PSK into chainingKey
3. Get three outputs: new chainingKey, tau, and tempKey
4. Mix tau into hash transcript
5. Use tempKey to encrypt/decrypt next message

### PSK in Message Flow

```
Message 1 (initiation):
- DH #1 and #2
- No PSK yet

Message 2 (response):
- DH #3 and #4
- Mix PSK (both sides have it)
- Encrypt empty payload with PSK-derived key
- If decryption succeeds → both have same PSK ✓
```

### When to Use PSK

**Use PSK when**:
- You want post-quantum resistance
- You can securely share a key out-of-band
- You want additional security layer

**Don't use PSK when**:
- You can't securely distribute the shared key
- Key management overhead isn't worth it

### Key Insight

PSK is optional but recommended for high-security scenarios. It's mixed
after DH operations, so it adds security without replacing public key
crypto. Think of it as "belt and suspenders" - if one fails, the other
protects you.

---

## 13. Message Wire Format

### Why Format Matters

Understanding the byte layout helps with:
- Debugging (hex dumps make sense)
- Implementation (correct parsing)
- Optimization (avoiding allocations)

### Message Type 1: Handshake Initiation (148 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=1    |   Reserved    |          Reserved             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Sender Index                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Ephemeral (32 bytes)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+              Encrypted Static (48 bytes)                      +
|                    (32 bytes key + 16 bytes tag)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+            Encrypted Timestamp (28 bytes)                     +
|                    (12 bytes time + 16 bytes tag)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        MAC1 (16 bytes)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        MAC2 (16 bytes)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Total: 1 + 3 + 4 + 32 + 48 + 28 + 16 + 16 = 148 bytes
```

**Fields**:
- **Type**: Always 1 for initiation
- **Reserved**: Must be zero (future use)
- **Sender Index**: Initiator's chosen index (identifies this session)
- **Ephemeral**: Initiator's ephemeral public key (plaintext)
- **Encrypted Static**: Initiator's static public key (encrypted + auth tag)
- **Encrypted Timestamp**: TAI64N timestamp (encrypted + auth tag)
- **MAC1**: DoS protection (always present)
- **MAC2**: Cookie (usually empty unless under load)

### Message Type 2: Handshake Response (92 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=2    |   Reserved    |          Reserved             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Sender Index                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Receiver Index                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Ephemeral (32 bytes)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Encrypted Empty (16 bytes)                 |
|                         (just auth tag)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        MAC1 (16 bytes)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        MAC2 (16 bytes)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Total: 1 + 3 + 4 + 4 + 32 + 16 + 16 + 16 = 92 bytes
```

**Fields**:
- **Type**: Always 2 for response
- **Sender Index**: Responder's chosen index
- **Receiver Index**: Initiator's index (from message 1)
- **Ephemeral**: Responder's ephemeral public key (plaintext)
- **Encrypted Empty**: AEAD tag proving responder completed handshake
- **MAC1/MAC2**: DoS protection

### Message Type 4: Transport Data (variable)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type=4    |   Reserved    |          Reserved             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Receiver Index                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Counter (8 bytes)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+               Encrypted Packet (variable)                     +
|                   (payload + 16 byte auth tag)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Minimum: 1 + 3 + 4 + 8 + 16 = 32 bytes (empty payload)
```

### Why These Sizes?

**Fixed sizes for handshake**:
- Prevents timing attacks (all handshakes same size)
- Simple parsing (no length fields needed)
- Predictable bandwidth

**Variable size for transport**:
- Accommodates any IP packet size
- Adds minimal overhead (32 bytes)

### Key Insight

Wire format is carefully designed. Fixed-size handshake messages prevent
information leakage. Minimal overhead on transport. Every byte has a
purpose - no wasted space.

---

## 14. Practical Debugging

### Adding Debug Logging

To understand handshake state, add logging at key points:

```go
// In CreateMessageInitiation
log.Printf("=== INITIATOR: Creating Message 1 ===")
log.Printf("Chaining Key: %x", state.chainingKey[:8])
log.Printf("Hash: %x", state.hash[:8])
log.Printf("Ephemeral Pub: %x", state.ephemeralPublic[:8])

// After each DH
log.Printf("After DH #1: chainingKey=%x", state.chainingKey[:8])
log.Printf("After DH #2: chainingKey=%x", state.chainingKey[:8])
```

**Pro tip**: Only log first 8 bytes to keep output readable.

### Comparing Initiator vs Responder

**Critical checkpoints** where values must match:

```
After Message 1 processed by responder:
✓ hash should match initiator's hash
✓ chainingKey should match initiator's chainingKey

After Message 2 processed by initiator:
✓ Both should have same final chainingKey
✓ Both should derive same sendKey/recvKey (but swapped)
```

### Testing State Sync

```go
// In tests, save state at each step
initiatorState := SaveState(initiator)
responderState := SaveState(responder)

// Compare
if !bytes.Equal(initiatorState.hash, responderState.hash) {
    t.Errorf("Hash mismatch after message 1")
    t.Logf("Initiator: %x", initiatorState.hash)
    t.Logf("Responder: %x", responderState.hash)
}
```

### Common Handshake Failures

**"MAC validation failed"**:
- Wrong peer public key in config
- MAC1 computation incorrect
- Message corrupted in transit

**"Decryption failed"**:
- ChainingKey out of sync (missed DH operation)
- Hash transcript mismatch (missed mixHash call)
- Wrong key used for decryption

**"Timestamp too old"**:
- Clock skew between peers
- Replay protection triggered
- Timestamp not in TAI64N format

**"No response received"**:
- Network issue (firewall, NAT)
- Responder rejected (under DoS load, requires MAC2)
- Endpoint incorrect

### Debugging with Wireshark

WireGuard packets are encrypted, but you can see:
- Packet sizes (148 for init, 92 for response)
- Message types (first byte)
- Timing (detect retransmissions)

### Using Go Debugger (delve)

```bash
# Set breakpoint in handshake
dlv test ./device
(dlv) break handshake.go:CreateMessageInitiation
(dlv) continue
(dlv) print state.chainingKey
(dlv) print state.hash
```

### Key Insight

Debugging handshakes requires patience. Add logging, compare states at
each step, and verify values match. Most issues are simple (wrong key,
missed operation) but hard to spot without visibility into internal state.

---

## 15. Attack Scenarios and Mitigations

### Attack 1: Passive Eavesdropping

**Attacker**: Listens to all traffic, records everything

**What they see**:
- Handshake messages (encrypted static keys, timestamps)
- Transport packets (all encrypted)
- Timing, sizes, endpoints

**What they CAN'T get**:
- Plaintext data (encryption)
- Static keys (encrypted with DH-derived keys)
- Session keys (require private keys)

**Mitigation**: All sensitive data encrypted. Even initiator identity is
hidden from passive observers (only responder can decrypt static key).

### Attack 2: Active Man-in-the-Middle

**Attacker**: Sits between peers, tries to intercept/modify

**Attempt 1: Modify handshake message**
- Change any byte in message 1
- Hash transcript changes
- Responder's AEAD decryption fails (auth tag mismatch)
- Handshake aborted ✓

**Attempt 2: Replay old handshake**
- Record valid message 1, replay later
- Timestamp check fails (too old)
- Replay protection triggers ✓

**Attempt 3: Impersonate peer**
- Send message 1 claiming to be Alice
- Don't have Alice's private key
- Can't compute DH(static_alice, static_bob)
- Responder's decryption fails ✓

**Mitigation**: Authentication via DH, integrity via AEAD, freshness via
timestamp. All three combined prevent MITM.

### Attack 3: What if We Remove Each DH?

**Remove DH #1 (ephemeral_i × static_r)**:
- Can't derive tempKey1
- Can't encrypt initiator's static key
- Identity hiding broken ❌
- Passive observers see who's connecting

**Remove DH #2 (static_i × static_r)**:
- No mutual authentication
- Initiator doesn't prove identity
- Responder accepts anyone ❌

**Remove DH #3 (ephemeral_i × ephemeral_r)**:
- No forward secrecy
- If static keys leak later, can decrypt past sessions ❌

**Remove DH #4 (static_i × ephemeral_r)**:
- Responder's ephemeral not bound to initiator
- Potential unknown key-share attack ❌

**Conclusion**: Every DH operation is essential. Remove any one → security
property breaks.

### Attack 4: DoS Amplification

**Without MAC1/MAC2**:
```
Attacker → Server: Random garbage (1000 packets/sec)
Server: Tries to process each one, wastes CPU
Server: Crashes or becomes unresponsive
```

**With MAC1**:
```
Attacker → Server: Random garbage
Server: Validates MAC1, fails immediately (cheap check)
Server: Drops packet, no expensive crypto
```

**With MAC2 (under load)**:
```
Attacker → Server: Valid MAC1, spoofed IP
Server: Sends cookie to spoofed IP (victim)
Attacker: Never receives cookie, can't send MAC2
Server: Rejects subsequent packets without MAC2
```

**Mitigation**: Stateless cookies prevent resource exhaustion. Server only
commits resources after validating sender can receive at that IP.

### Attack 5: Replay Attack in Detail

**Scenario**: Attacker records valid transport packet

**Attempt to replay**:
```
Original packet: counter=42, encrypted with nonce=42
Replay same packet later
Receiver: Checks counter against replay window
Counter 42 already seen → REJECT ✓
```

**Why timestamp in handshake isn't enough**:
- Handshake timestamp prevents replaying old handshakes
- Transport packets need per-packet replay protection
- Use counter + sliding window (see section on replay protection)

### Key Insight

WireGuard's security comes from layered defenses. Each mechanism addresses
specific threats. Understanding attacks helps you appreciate why each
piece is necessary. Nothing is arbitrary - everything serves a purpose.
