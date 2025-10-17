# 🔒 P2P Chat - Secure Terminal Chat

Terminal-based peer-to-peer chat with military-grade end-to-end encryption, no servers required.

[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](https://github.com/yourusername/p2p_chat)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9.3-blue)](https://www.typescriptlang.org/)

---

## Features

### Security First
- **E2E Encryption**: AES-256-GCM authenticated encryption
- **Digital Signatures**: Ed25519 signatures verify message authenticity
- **Replay Protection**: Nonces and timestamp validation prevent replay attacks
- **DoS Protection**: Connection limits and timeouts prevent resource exhaustion
- **PBKDF2 Key Derivation**: 100,000 iterations protect against brute force
- **Minimal Metadata**: PeerID and timestamps encrypted, reducing traffic analysis

### True P2P
- **No Central Servers**: Uses Hyperswarm DHT for peer discovery
- **Global Reach**: Works across the Internet, not just LAN
- **NAT Traversal**: Built-in hole punching for firewall/NAT traversal
- **Decentralized**: No single point of failure

### Privacy
- **Persistent Identity**: Cryptographic identity persists across sessions
- **Room-based**: Join encrypted rooms with shared codes
- **No Registration**: No accounts, emails, or personal data
- **Local Storage**: Keys stored only on your machine (`~/.p2p_chat/`)

---

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/sergiobonatto/p2p_chat.git
cd p2p_chat

# Install dependencies
npm install

# Build
npm run build
```

### Usage

```bash
# Start chat
npm start

# Enter room code when prompted
Código da sala (use algo forte): my-secret-room-code-2024

# Start chatting!
```

### First Run

On first run, a cryptographic keypair and peer ID are automatically generated and stored securely:

```
Chave privada gerada e salva em ~/.p2p_chat/key.pem
peerId gerado e salvo em ~/.p2p_chat/peerid.txt: a1b2c3
```

These persist across sessions, maintaining your identity.

---

## 📖 How It Works

### Architecture

```
┌─────────────┐         DHT          ┌─────────────┐
│   Peer A    │ ◄─────Discovery────► │   Peer B    │
│             │                      │             │
│  Ed25519    │    Direct P2P TCP    │  Ed25519    │
│  Keypair    │ ◄────Connection────► │  Keypair    │
│             │                      │             │
│   AES-256   │                      │   AES-256   │
│   Encrypt   │ ──────Message──────► │   Decrypt   │
│   + Sign    │                      │   + Verify  │
└─────────────┘                      └─────────────┘
```

### Security Flow

1. **Key Derivation**: Room code → PBKDF2(100k iter) → AES-256 key
2. **Discovery**: SHA-256(code) → DHT topic → Find peers
3. **Handshake**: Exchange Ed25519 public keys
4. **Message Send**:
   - JSON payload → Ed25519 sign → AES-256-GCM encrypt → Send
5. **Message Receive**:
   - Receive → AES-256-GCM decrypt → Ed25519 verify → Display

### Message Structure

**Encrypted Payload** (inside AES-256-GCM):
```json
{
  "peerId": "a1b2c3",
  "text": "Hello, world!",
  "ts": 1729180800000,
  "nonce": "unique_random_16bytes",
  "seq": 42
}
```

**Wire Format** (what travels on network):
```json
{
  "type": "enc",
  "payload": "base64(iv||ciphertext||tag||signature)"
}
```

---

## 🔧 Configuration

### Constants (in `src/index.ts`)

```typescript
MAX_MESSAGE_AGE_MS = 5 * 60 * 1000        // 5 minutes
MAX_MESSAGE_FUTURE_MS = 60 * 1000         // 1 minute
NONCE_CACHE_SIZE = 1000                   // 1000 nonces/peer
MAX_CONNECTIONS = 50                      // 50 simultaneous peers
CONNECTION_TIMEOUT_MS = 60 * 1000         // 60 seconds
PBKDF2_ITERATIONS = 100000                // OWASP recommended
```

Adjust these in the source code as needed for your use case.

---

## 🛡️ Security Features

### ✅ Implemented (v0.2.0)

| Feature | Status | Description |
|---------|--------|-------------|
| **E2E Encryption** | ✅ | AES-256-GCM with authenticated encryption |
| **Digital Signatures** | ✅ | Ed25519 signatures on all messages |
| **Replay Protection** | ✅ | Nonce + timestamp validation |
| **DoS Protection** | ✅ | Connection limits + timeouts |
| **PBKDF2** | ✅ | 100k iterations for key derivation |
| **Message Ordering** | ✅ | Sequence numbers detect out-of-order |
| **Memory Safety** | ✅ | Automatic cleanup on disconnect |
| **Metadata Privacy** | ✅ | PeerID/timestamp in encrypted payload |

---

## 🧪 Testing

### Basic Functionality
```bash
# Terminal 1
npm start
# Enter code: test-room-123

# Terminal 2
npm start
# Enter code: test-room-123

# Type messages in either terminal
```

### Security Tests

**Replay Attack Test**:
1. Capture traffic with Wireshark
2. Resend a captured message
3. Should see: `[enc] REPLAY ATTACK detected`

**DoS Test**:
1. Open 51+ connections simultaneously
2. 51st should be rejected: `[rejected] max connections reached`

**Timeout Test**:
1. Connect and remain idle for 60+ seconds
2. Should see: `[timeout] idle timeout, closing connection`

---

## 📁 Project Structure

```
p2p_chat/
├── src/
│   ├── index.ts           # Main application
│   └── hyperswarm.d.ts    # TypeScript definitions
├── package.json           # Dependencies
├── tsconfig.json          # TypeScript config
├── SECURITY_IMPROVEMENTS.md  # Security changelog
├── MIGRATION_GUIDE.md     # v0.1 → v0.2 migration
└── README.md             # This file
```

---

## Key Management

### Storage Location
```
~/.p2p_chat/
├── key.pem       # Ed25519 private key (PKCS#8 PEM, mode 0600)
└── peerid.txt    # Your peer identifier (mode 0600)
```

### Backup Your Keys

**IMPORTANT**: Backup these files to preserve your identity:

```bash
# Backup
cp -r ~/.p2p_chat ~/p2p_chat_backup

# Restore
cp -r ~/p2p_chat_backup ~/.p2p_chat
```

### Generate New Identity

```bash
# Delete existing keys
rm -rf ~/.p2p_chat

# Run chat - new keys will be generated
npm start
```

---

## 🐛 Troubleshooting

### "could not decrypt/verify message"
**Cause**: Peer using different room code or different version.

**Fix**: Ensure all peers use exact same code (case-sensitive!) and same version.

### "max connections reached"
**Cause**: More than 50 simultaneous connections.

**Fix**: Increase `MAX_CONNECTIONS` in source code, or split into multiple rooms.

### "REPLAY ATTACK detected"
**Cause**: Duplicate message received (could be network issue or actual attack).

**Action**: If frequent, investigate. Occasional is normal.

### Slow to join room
**Cause**: PBKDF2 takes ~50ms (by design for security).

**Action**: This is normal. Wait a moment.
