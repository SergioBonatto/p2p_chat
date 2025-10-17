// src/index.ts
import Hyperswarm from 'hyperswarm';
import crypto from 'crypto';
import readline from 'readline';
import fs from 'fs';
import os from 'os';
import path from 'path';
/**
 * Versão com persistência de chave privada e peerId:
 * - diretório: ~/.p2p_chat/
 * - arquivos:
 *    - key.pem       (private key PEM PKCS#8, mode 0600)
 *    - peerid.txt    (peerId, mode 0600)
 *
 * Funcionalidade mantém:
 * - AES-256-GCM E2E via chave derivada do código da sala
 * - Assinatura Ed25519 das mensagens
 * - Hyperswarm DHT discovery
 */
// ----- Config de persistência -----
const STORAGE_DIR = path.join(os.homedir(), '.p2p_chat');
const KEY_PATH = path.join(STORAGE_DIR, 'key.pem');
const PEERID_PATH = path.join(STORAGE_DIR, 'peerid.txt');
// ----- Constants -----
const MAX_MESSAGE_AGE_MS = 5 * 60 * 1000; // 5 minutes
const MAX_MESSAGE_FUTURE_MS = 60 * 1000; // 1 minute (clock skew tolerance)
const NONCE_CACHE_SIZE = 1000; // keep last 1000 nonces per peer
const MAX_CONNECTIONS = 50; // maximum simultaneous connections
const CONNECTION_TIMEOUT_MS = 60 * 1000; // 60 seconds idle timeout
const PBKDF2_ITERATIONS = 100000; // OWASP recommended minimum
const PBKDF2_KEYLEN = 32; // 256 bits for AES-256
// ----- Helpers -----
function msgToBuffer(obj) {
    return Buffer.from(JSON.stringify(obj) + '\n', 'utf8');
}
function parseLines(buffered, carry) {
    const data = carry + buffered.toString('utf8');
    const parts = data.split('\n');
    const carryOut = parts.pop() || '';
    return { lines: parts.filter(Boolean), carry: carryOut };
}
function makePeerId() {
    return crypto.randomBytes(6).toString('hex');
}
function makeNonce() {
    return crypto.randomBytes(16).toString('base64');
}
function deriveKeyFromCode(code) {
    // Use PBKDF2 for key derivation with fixed salt derived from code
    // Note: In a perfect world, we'd use a random salt stored with the key,
    // but since this is a shared room code system, we derive a deterministic
    // salt from the code itself so all peers derive the same key
    const salt = crypto.createHash('sha256').update('p2p_chat_salt_v1:' + code).digest();
    // Synchronous PBKDF2 with SHA-256
    return crypto.pbkdf2Sync(code, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, 'sha256');
}
// Validate message timestamp to prevent replay of old messages
function isTimestampValid(ts) {
    const now = Date.now();
    const age = now - ts;
    const future = ts - now;
    // Reject messages too old
    if (age > MAX_MESSAGE_AGE_MS) {
        return false;
    }
    // Reject messages too far in the future (clock skew tolerance)
    if (future > MAX_MESSAGE_FUTURE_MS) {
        return false;
    }
    return true;
}
// encrypt plaintext (utf8) -> base64(iv || ciphertext || tag || signature)
function encryptWithSignature(plaintext, key, signKey) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    // signature over plaintext (utf8)
    const signature = crypto.sign(null, Buffer.from(plaintext, 'utf8'), signKey); // Ed25519
    const out = Buffer.concat([iv, ciphertext, tag, signature]);
    return out.toString('base64');
}
// decrypt base64(iv||ciphertext||tag||signature) -> { plaintext, signature: Buffer }
function decryptAndExtractSignature(base64payload, key) {
    const buf = Buffer.from(base64payload, 'base64');
    if (buf.length < 12 + 16 + 64)
        throw new Error('payload too short');
    const iv = buf.slice(0, 12);
    const signature = buf.slice(buf.length - 64); // last 64 bytes
    const tag = buf.slice(buf.length - 64 - 16, buf.length - 64);
    const ciphertext = buf.slice(12, buf.length - 64 - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return { plaintext: pt.toString('utf8'), signature };
}
// ----- Persistence utilities -----
function ensureStorageDir() {
    try {
        fs.mkdirSync(STORAGE_DIR, { recursive: true, mode: 0o700 });
    }
    catch (e) {
        // ignore if already exists
    }
}
function saveFileSecure(p, content) {
    // write file and set permission 600
    fs.writeFileSync(p, content, { mode: 0o600 });
}
function loadPrivateKeyOrCreate() {
    ensureStorageDir();
    if (fs.existsSync(KEY_PATH)) {
        const pem = fs.readFileSync(KEY_PATH, 'utf8');
        const priv = crypto.createPrivateKey({ key: pem, format: 'pem', type: 'pkcs8' });
        const pub = crypto.createPublicKey(priv);
        return { privateKey: priv, publicKey: pub, created: false };
    }
    else {
        // generate new keypair
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        // export private key PEM PKCS#8
        const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
        saveFileSecure(KEY_PATH, privPem);
        // ensure mode correct (some platforms ignore mode in writeFileSync), set explicitly
        try {
            fs.chmodSync(KEY_PATH, 0o600);
        }
        catch { /* ignore */ }
        const pub = crypto.createPublicKey(privateKey);
        return { privateKey, publicKey: pub, created: true };
    }
}
function loadOrCreatePeerId() {
    ensureStorageDir();
    if (fs.existsSync(PEERID_PATH)) {
        const pid = fs.readFileSync(PEERID_PATH, 'utf8').trim();
        return { peerId: pid, created: false };
    }
    else {
        const pid = makePeerId();
        saveFileSecure(PEERID_PATH, pid);
        try {
            fs.chmodSync(PEERID_PATH, 0o600);
        }
        catch { /* ignore */ }
        return { peerId: pid, created: true };
    }
}
// ----- Main -----
async function main() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    const question = (q) => new Promise((res) => rl.question(q, res));
    const code = (await question('Código da sala (use algo forte): ')).trim();
    if (!code) {
        console.log('Código inválido');
        process.exit(1);
    }
    // load or create persistent keypair and peerId
    const keypair = loadPrivateKeyOrCreate();
    const peerIdObj = loadOrCreatePeerId();
    const peerId = peerIdObj.peerId;
    if (keypair.created) {
        console.log(`Chave privada gerada e salva em ${KEY_PATH}`);
    }
    else {
        console.log(`Chave privada carregada de ${KEY_PATH}`);
    }
    if (peerIdObj.created) {
        console.log(`peerId gerado e salvo em ${PEERID_PATH}: ${peerId}`);
    }
    else {
        console.log(`peerId carregado: ${peerId}`);
    }
    // export public key DER SPKI base64 (to send in hello)
    const pubDer = keypair.publicKey.export({ type: 'spki', format: 'der' });
    const pubDerB64 = pubDer.toString('base64');
    const key = deriveKeyFromCode(code); // symmetric AES-256 key
    const topic = crypto.createHash('sha256').update(code).digest();
    const swarm = new Hyperswarm();
    swarm.on('error', (err) => console.error('swarm error', err));
    // store mapping peerId -> PublicKey object (crypto.KeyObject) for signature verification
    const peerPubKeys = new Map();
    // store nonces per peer to prevent replay attacks
    // Map<peerId, Set<nonce>>
    const peerNonces = new Map();
    // store last seen sequence number per peer for ordering
    // Map<peerId, lastSeq>
    const peerSequences = new Map();
    // our own sequence counter for outgoing messages
    let mySequence = 0;
    // Check if nonce was already seen (replay attack detection)
    function isNonceUsed(peerId, nonce) {
        const nonces = peerNonces.get(peerId);
        return nonces ? nonces.has(nonce) : false;
    }
    // Add nonce to seen list with LRU-like cleanup
    function addNonce(peerId, nonce) {
        let nonces = peerNonces.get(peerId);
        if (!nonces) {
            nonces = new Set();
            peerNonces.set(peerId, nonces);
        }
        // Simple LRU: if cache is full, clear it
        // (In production, use proper LRU cache with timestamps)
        if (nonces.size >= NONCE_CACHE_SIZE) {
            nonces.clear();
        }
        nonces.add(nonce);
    }
    const sockets = new Set();
    swarm.on('connection', (socket, details) => {
        const remoteAddr = `${details.peer?.host ?? '?'}:${details.peer?.port ?? '?'}`;
        // DoS Protection: limit maximum connections
        if (sockets.size >= MAX_CONNECTIONS) {
            console.log(`[rejected] connection from ${remoteAddr} — max connections (${MAX_CONNECTIONS}) reached`);
            socket.destroy();
            return;
        }
        console.log(`\n[connected] new connection from ${remoteAddr} (${sockets.size + 1}/${MAX_CONNECTIONS})`);
        sockets.add(socket);
        // Set socket timeout to prevent resource exhaustion from idle connections
        socket.setTimeout(CONNECTION_TIMEOUT_MS);
        let carry = '';
        let remotePeerId = 'unknown';
        socket.on('data', (chunk) => {
            const { lines, carry: newCarry } = parseLines(chunk, carry);
            carry = newCarry;
            for (const line of lines) {
                try {
                    const m = JSON.parse(line);
                    if (m.type === 'hello') {
                        remotePeerId = m.peerId ?? remotePeerId;
                        if (m.pubKey) {
                            try {
                                const pubBuf = Buffer.from(m.pubKey, 'base64');
                                const pubKeyObj = crypto.createPublicKey({ key: pubBuf, format: 'der', type: 'spki' });
                                peerPubKeys.set(remotePeerId, pubKeyObj);
                                console.log(`[hello] ${remotePeerId} connected (${remoteAddr}) — pubKey stored`);
                            }
                            catch (e) {
                                console.log(`[hello] ${remotePeerId} connected (${remoteAddr}) — could not parse pubKey`);
                            }
                        }
                        else {
                            console.log(`[hello] ${remotePeerId} connected (${remoteAddr}) — no pubKey`);
                        }
                    }
                    else if (m.type === 'enc') {
                        if (!m.payload) {
                            console.log('[warn] enc message without payload');
                            continue;
                        }
                        try {
                            const { plaintext, signature } = decryptAndExtractSignature(m.payload, key);
                            // try parse plaintext JSON
                            let parsed = null;
                            try {
                                parsed = JSON.parse(plaintext);
                            }
                            catch {
                                console.log('[enc] failed to parse message payload');
                                continue;
                            }
                            if (!parsed || !parsed.peerId || !parsed.text || !parsed.ts || !parsed.nonce) {
                                console.log('[enc] message missing required fields');
                                continue;
                            }
                            const claimedPeer = parsed.peerId;
                            // Validate timestamp to prevent replay of old messages
                            if (!isTimestampValid(parsed.ts)) {
                                console.log(`[enc] message from ${claimedPeer} rejected: timestamp out of acceptable range`);
                                continue;
                            }
                            // Check for replay attack (duplicate nonce)
                            if (isNonceUsed(claimedPeer, parsed.nonce)) {
                                console.log(`[enc] REPLAY ATTACK detected from ${claimedPeer} — duplicate nonce, message discarded`);
                                continue;
                            }
                            const pub = peerPubKeys.get(claimedPeer);
                            if (!pub) {
                                console.log(`[enc] received from ${claimedPeer} but have no pubKey yet — message could not be verified`);
                                continue;
                            }
                            // verify signature
                            const ok = crypto.verify(null, Buffer.from(plaintext, 'utf8'), pub, signature);
                            if (!ok) {
                                console.log(`[enc] signature INVALID for ${claimedPeer} — message discarded`);
                                continue;
                            }
                            // All checks passed - add nonce to prevent replay
                            addNonce(claimedPeer, parsed.nonce);
                            // Check sequence number for ordering (if present)
                            if (parsed.seq !== undefined) {
                                const lastSeq = peerSequences.get(claimedPeer) ?? -1;
                                if (parsed.seq <= lastSeq) {
                                    console.log(`[warn] out-of-order message from ${claimedPeer}: seq ${parsed.seq} (expected > ${lastSeq})`);
                                }
                                peerSequences.set(claimedPeer, Math.max(lastSeq, parsed.seq));
                            }
                            // Display message
                            const t = new Date(parsed.ts).toLocaleTimeString();
                            console.log(`[${t}] ${claimedPeer}: ${parsed.text}`);
                        }
                        catch (e) {
                            console.log(`[enc] could not decrypt/verify message — ${String(e)}`);
                        }
                    }
                }
                catch (e) {
                    // ignore parse error
                }
            }
        });
        socket.on('close', () => {
            sockets.delete(socket);
            // Clean up memory: remove peer's public key, nonces, and sequence tracking
            if (remotePeerId && remotePeerId !== 'unknown') {
                peerPubKeys.delete(remotePeerId);
                peerNonces.delete(remotePeerId);
                peerSequences.delete(remotePeerId);
            }
            console.log(`[disconnected] ${remotePeerId} (${remoteAddr})`);
        });
        socket.on('error', (err) => {
            sockets.delete(socket);
            console.log(`[socket error] ${err?.message ?? err}`);
        });
        socket.on('timeout', () => {
            console.log(`[timeout] ${remotePeerId} (${remoteAddr}) — idle timeout, closing connection`);
            socket.destroy();
        });
        // send hello with pubKey (base64 DER)
        socket.write(msgToBuffer({ type: 'hello', peerId, pubKey: pubDerB64 }));
    });
    swarm.join(topic, {
        lookup: true,
        announce: true
    });
    await swarm.flush();
    console.log(`Entrou na sala '${code}'. Aguardando peers... (digite /quit para sair)`);
    rl.on('line', (line) => {
        const text = line.trim();
        if (!text)
            return;
        if (text === '/quit') {
            console.log('Saindo...');
            rl.close();
            swarm.destroy();
            sockets.forEach((s) => s.destroy());
            process.exit(0);
        }
        // build plaintext payload as JSON with nonce for replay protection and sequence number for ordering
        const payloadObj = {
            peerId,
            text,
            ts: Date.now(),
            nonce: makeNonce(),
            seq: mySequence++
        };
        const plaintext = JSON.stringify(payloadObj);
        // encrypt and sign
        const b64 = encryptWithSignature(plaintext, key, keypair.privateKey);
        // Note: peerId removed from outer message to reduce metadata leakage
        // It's now only in the encrypted payload
        const message = { type: 'enc', payload: b64 };
        const buf = msgToBuffer(message);
        for (const s of Array.from(sockets)) {
            if (!s.destroyed) {
                try {
                    s.write(buf);
                }
                catch (e) { /* ignore */ }
            }
        }
        const now = new Date(message.ts).toLocaleTimeString();
        console.log(`[${now}] você: ${text}`);
    });
}
main().catch((err) => {
    console.error(err);
    process.exit(1);
});
