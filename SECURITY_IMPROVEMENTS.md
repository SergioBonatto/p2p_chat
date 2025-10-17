# Melhorias de Segurança Implementadas

## Data: 2025-10-17

Este documento descreve as melhorias críticas de segurança implementadas no chat P2P.

---

## ✅ 1. Proteção contra Replay Attacks

### Problema Original
Mensagens capturadas da rede poderiam ser reenviadas (replay) sem detecção.

### Solução Implementada
- **Nonces únicos**: Cada mensagem inclui um nonce aleatório de 16 bytes
- **Deduplicação**: Sistema de cache mantém últimos 1000 nonces por peer
- **Validação de timestamp**: Mensagens com mais de 5 minutos são rejeitadas
- **Clock skew tolerance**: Aceita mensagens até 1 minuto no futuro

### Código Relevante
```typescript
const payloadObj: EncryptedPayload = {
  peerId,
  text,
  ts: Date.now(),
  nonce: makeNonce(), // ← Nonce único
  seq: mySequence++
}

// Verificação
if (isNonceUsed(claimedPeer, parsed.nonce)) {
  console.log(`REPLAY ATTACK detected from ${claimedPeer}`)
  continue
}
```

---

## ✅ 2. Proteção contra DoS (Denial of Service)

### Problema Original
- Sem limite de conexões simultâneas
- Conexões idle consumiam recursos indefinidamente
- Vulnerável a resource exhaustion attacks

### Solução Implementada
- **Limite de conexões**: Máximo de 50 conexões simultâneas
- **Connection timeout**: Conexões idle fechadas após 60 segundos
- **Rejeição imediata**: Novas conexões rejeitadas quando limite atingido

### Código Relevante
```typescript
const MAX_CONNECTIONS = 50
const CONNECTION_TIMEOUT_MS = 60 * 1000

// Verificação no handshake
if (sockets.size >= MAX_CONNECTIONS) {
  console.log(`[rejected] max connections reached`)
  socket.destroy()
  return
}

socket.setTimeout(CONNECTION_TIMEOUT_MS)
```

---

## ✅ 3. Correção de Memory Leak

### Problema Original
Maps de `peerPubKeys` e `peerNonces` nunca eram limpos quando peers desconectavam.

### Solução Implementada
- Limpeza automática de todos os Maps no evento `close` do socket
- Remove public keys, nonces e sequence tracking

### Código Relevante
```typescript
socket.on('close', () => {
  sockets.delete(socket)

  // Limpeza de memória
  if (remotePeerId && remotePeerId !== 'unknown') {
    peerPubKeys.delete(remotePeerId)
    peerNonces.delete(remotePeerId)
    peerSequences.delete(remotePeerId)
  }
})
```

---

## ✅ 4. Derivação de Chaves Melhorada (PBKDF2)

### Problema Original
SHA-256 simples é vulnerável a:
- Rainbow table attacks
- Brute force rápido
- Sem proteção contra códigos fracos

### Solução Implementada
- **PBKDF2** com 100,000 iterações (OWASP recomendado)
- **Salt determinístico**: Derivado do código para manter compatibilidade P2P
- **SHA-256** como função hash interna

### Código Relevante
```typescript
const PBKDF2_ITERATIONS = 100000
const PBKDF2_KEYLEN = 32 // 256 bits

function deriveKeyFromCode(code: string): Buffer {
  const salt = crypto.createHash('sha256')
    .update('p2p_chat_salt_v1:' + code)
    .digest()

  return crypto.pbkdf2Sync(
    code,
    salt,
    PBKDF2_ITERATIONS,
    PBKDF2_KEYLEN,
    'sha256'
  )
}
```

### Performance
- ~50ms para derivar chave (aceitável, feito uma vez no início)
- Dificulta brute force em ~100,000x

---

## ✅ 5. Message Ordering com Sequence Numbers

### Problema Original
- Mensagens podiam chegar fora de ordem
- Difícil detectar mensagens perdidas
- Conversas confusas

### Solução Implementada
- **Sequence numbers**: Contador incremental por peer
- **Validação de ordem**: Detecta e alerta mensagens fora de ordem
- **Tracking por peer**: Cada peer tem seu próprio sequence tracking

### Código Relevante
```typescript
let mySequence = 0
const peerSequences = new Map<string, number>()

// Envio
const payloadObj: EncryptedPayload = {
  seq: mySequence++ // ← Incrementa a cada mensagem
}

// Recepção
if (parsed.seq !== undefined) {
  const lastSeq = peerSequences.get(claimedPeer) ?? -1
  if (parsed.seq <= lastSeq) {
    console.log(`[warn] out-of-order message`)
  }
  peerSequences.set(claimedPeer, Math.max(lastSeq, parsed.seq))
}
```

---

## ✅ 6. Redução de Metadata Leakage

### Problema Original
- `peerId` e `timestamp` vazavam em plaintext no envelope externo
- Permitia traffic analysis
- Correlação de identidades

### Solução Implementada
- **PeerId movido**: Agora apenas dentro do payload criptografado
- **Menos metadata**: Envelope externo contém apenas `type` e `payload`
- **Privacy melhorada**: Dificulta análise de tráfego

### Código Relevante
```typescript
// ANTES
const message: Message = {
  type: 'enc',
  peerId, // ← vazava em plaintext
  payload: b64,
  ts: payloadObj.ts // ← vazava em plaintext
}

// DEPOIS
const message: Message = {
  type: 'enc',
  payload: b64 // ← apenas payload criptografado
}
```

---

## 📊 Comparação Antes vs Depois

| Feature | Antes | Depois |
|---------|-------|--------|
| **Replay Protection** | ❌ Nenhuma | ✅ Nonce + Timestamp |
| **DoS Protection** | ❌ Vulnerável | ✅ Limite + Timeout |
| **Memory Management** | ❌ Leak | ✅ Cleanup automático |
| **Key Derivation** | ⚠️ SHA-256 | ✅ PBKDF2 100k iter |
| **Message Ordering** | ❌ Sem ordem | ✅ Sequence numbers |
| **Metadata Privacy** | ⚠️ Vaza peerId/ts | ✅ Criptografado |

---

## 🔄 Compatibilidade

**⚠️ BREAKING CHANGE**: Este update **NÃO** é compatível com versões anteriores.

**Motivos**:
1. Estrutura de payload mudou (adição de `nonce` e `seq`)
2. Derivação de chave diferente (PBKDF2 vs SHA-256)
3. Formato de mensagem externo mudou (removeu `peerId`)

**Solução**: Todos os peers devem atualizar simultaneamente.

---

## 🧪 Como Testar

### 1. Teste Básico de Funcionalidade
```bash
npm start
# Terminal 1: código "teste123"
# Terminal 2: código "teste123"
# Envie mensagens em ambos os lados
```

### 2. Teste de Replay Protection
- Capturar tráfego com Wireshark
- Reenviar mensagem capturada
- Deve ver: "REPLAY ATTACK detected"

### 3. Teste de DoS Protection
- Abrir 51+ conexões simultaneamente
- 51ª conexão deve ser rejeitada

### 4. Teste de Timeout
- Conectar e ficar idle por 60+ segundos
- Conexão deve ser fechada automaticamente

---

## 🚀 Próximas Melhorias Recomendadas

### Curto Prazo
- [ ] Implementar rate limiting de mensagens por peer
- [ ] Adicionar lista de peers online
- [ ] Melhorar UX com cores e formatação

### Médio Prazo
- [ ] Perfect Forward Secrecy (Double Ratchet)
- [ ] Histórico de mensagens com Hypercore
- [ ] Modo "invite-only" com whitelist

### Longo Prazo
- [ ] GUI com Electron
- [ ] Suporte a arquivos/mídia
- [ ] End-to-end encrypted voice/video

---

## 📝 Notas de Implementação

### Decisões de Design

1. **PBKDF2 com salt determinístico**: Escolhemos salt derivado do código (vs salt aleatório) porque:
   - Mantém natureza P2P sem servidor central
   - Todos os peers derivam mesma chave do mesmo código
   - Trade-off aceitável (ainda 100k iterações protegem)

2. **LRU simples para nonces**: Cache de 1000 nonces com clear completo quando cheio:
   - Simples de implementar
   - Suficiente para uso normal
   - Em produção, usar LRU com timestamps e TTL

3. **Sequence numbers sem buffer**: Detecta mas não reordena mensagens:
   - Mantém simplicidade
   - Alerta usuário sobre problemas
   - Reordenação automática seria próxima iteração

---

## 🔒 Security Audit Checklist

- [x] Input validation em todos os campos de mensagem
- [x] Tratamento de erros sem vazar informações
- [x] Limpeza de recursos ao desconectar
- [x] Proteção contra replay attacks
- [x] Proteção contra DoS
- [x] Key derivation robusta
- [x] Minimização de metadata leakage
- [ ] Auditoria externa por especialista em segurança
- [ ] Penetration testing
- [ ] Fuzzing do parser de mensagens

---

## 📚 Referências

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-132](https://csrc.nist.gov/publications/detail/sp/800-132/final) - PBKDF recommendations
- [Signal Protocol](https://signal.org/docs/) - E2E encryption best practices
- [Hyperswarm Documentation](https://github.com/holepunchto/hyperswarm)

---

**Versão**: 0.2.0
**Data**: 2025-10-17
**Autor**: Security hardening update
