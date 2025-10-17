# Guia de Migração v0.1 → v0.2

## ⚠️ IMPORTANTE: Breaking Changes

A versão 0.2.0 introduz mudanças significativas de segurança que **quebram compatibilidade** com v0.1.0.

---

## O Que Mudou?

### 1. Formato de Mensagens
**v0.1.0** (antigo):
```json
{
  "type": "enc",
  "peerId": "abc123",
  "payload": "...",
  "ts": 1234567890
}
```

**v0.2.0** (novo):
```json
{
  "type": "enc",
  "payload": "..."
}
```

**Impacto**: PeerId e timestamp agora estão dentro do payload criptografado.

---

### 2. Derivação de Chaves
**v0.1.0** (antigo):
```typescript
// SHA-256 simples
crypto.createHash('sha256').update(code).digest()
```

**v0.2.0** (novo):
```typescript
// PBKDF2 com 100,000 iterações
crypto.pbkdf2Sync(code, salt, 100000, 32, 'sha256')
```

**Impacto**: Mesmo código da sala gera chaves diferentes. Peers em v0.1 e v0.2 **não podem se comunicar**.

---

### 3. Estrutura do Payload Criptografado
**v0.1.0** (antigo):
```json
{
  "peerId": "abc123",
  "text": "mensagem",
  "ts": 1234567890
}
```

**v0.2.0** (novo):
```json
{
  "peerId": "abc123",
  "text": "mensagem",
  "ts": 1234567890,
  "nonce": "unique_random_value",
  "seq": 42
}
```

**Impacto**: Campos adicionais obrigatórios.

---

## Como Migrar?

### Opção 1: Atualização Coordenada (Recomendado)
Ideal para grupos pequenos onde você pode coordenar a atualização.

1. **Combine um horário** com todos do grupo
2. **Todos param** o chat antigo
3. **Todos atualizam** para v0.2.0:
   ```bash
   cd p2p_chat
   git pull  # ou baixe nova versão
   npm install
   npm run build
   ```
4. **Todos reiniciam** usando o mesmo código de sala

### Opção 2: Nova Sala
Ideal se coordenação é difícil.

1. Atualize para v0.2.0
2. **Use um novo código de sala** (ex: se era "sala123", use "sala123-v2")
3. Comunique o novo código para outros membros
4. Migre gradualmente conforme membros atualizam

### Opção 3: Executar Ambas Versões Temporariamente
Para grupos grandes com migração gradual.

1. Clone o repositório em diretório diferente:
   ```bash
   cp -r p2p_chat p2p_chat_v2
   cd p2p_chat_v2
   git pull
   npm install
   npm run build
   ```
2. Mantenha v0.1 rodando na sala antiga
3. Inicie v0.2 em nova sala
4. Quando todos migrarem, descontinue v0.1

---

## Verificando Versão

### v0.1.0
- Não tem proteção contra replay
- Log não menciona "nonce" ou "seq"
- Conexão instantânea (sem delay do PBKDF2)

### v0.2.0
- Log mostra conexões como "X/50"
- Pequeno delay (~50ms) ao entrar na sala (PBKDF2)
- Log menciona "replay attack" se detectar replays
- Avisos de "out-of-order message" se aplicável

---

## FAQ

### P: Posso usar o mesmo código de sala após atualizar?
**R**: Sim, mas todos devem estar na v0.2.0. A derivação de chave é diferente, então v0.1 e v0.2 não se comunicam mesmo com o mesmo código.

### P: Minhas chaves privadas e peerId serão preservados?
**R**: ✅ **SIM**! Os arquivos `~/.p2p_chat/key.pem` e `~/.p2p_chat/peerid.txt` são compatíveis e não mudam.

### P: Preciso fazer backup antes de atualizar?
**R**: Recomendado, mas não essencial. As chaves são compatíveis. Backup:
```bash
cp -r ~/.p2p_chat ~/.p2p_chat.backup
```

### P: E se alguém do grupo não atualizar?
**R**: Eles **não conseguirão** se comunicar. Mensagens falharão na descriptografia. Solução:
- Use sala separada temporariamente, OU
- Ajude-os a atualizar

### P: A atualização é obrigatória?
**R**: Se você quer se comunicar com peers na v0.2, sim. v0.1 continua funcional para grupos que não atualizaram.

### P: Há risco de perder mensagens?
**R**: Não há histórico persistente em nenhuma versão. Mensagens existem apenas enquanto o chat está aberto.

---

## Testando Após Migração

### ✅ Checklist de Testes

1. **Inicialização**:
   ```bash
   npm start
   ```
   - [ ] Carrega chave privada existente
   - [ ] Carrega peerId existente
   - [ ] Leve delay ao entrar (~50ms é normal)

2. **Conexão**:
   - [ ] Aparece "X/50" no log de conexões
   - [ ] Mensagem de "hello" recebida

3. **Envio de Mensagens**:
   - [ ] Sua mensagem aparece com timestamp
   - [ ] Outros peers recebem

4. **Recebimento**:
   - [ ] Mensagens de outros aparecem
   - [ ] Timestamp correto
   - [ ] Sem erros de verificação

5. **Segurança**:
   - [ ] Nenhum "REPLAY ATTACK" em uso normal
   - [ ] Sem "out-of-order message" em uso normal
   - [ ] Timeout funciona após 60s de idle

---

## Rollback (Reverter para v0.1)

Se precisar voltar para v0.1.0:

1. **Parar v0.2**
2. **Restaurar código antigo**:
   ```bash
   git checkout v0.1.0  # ou tag/commit da v0.1
   npm install
   npm run build
   ```
3. **Iniciar**:
   ```bash
   npm start
   ```

⚠️ **Suas chaves e peerId são preservados** - funcionam em ambas versões.

---

## Problemas Comuns

### "could not decrypt/verify message"
**Causa**: Outro peer está em versão diferente ou código de sala errado.

**Solução**:
1. Confirme que todos estão na mesma versão
2. Confirme o código da sala (case-sensitive!)

### "REPLAY ATTACK detected"
**Causa Normal**: Falso positivo se:
- Reiniciou e nonce cache foi limpo
- Mensagem antiga ressincronizada

**Causa Suspeita**: Alguém realmente reenviando mensagens.

**Ação**: Se acontece frequentemente, investigue.

### "max connections reached"
**Causa**: Mais de 50 peers tentando conectar simultaneamente.

**Solução**:
1. Para grupos grandes, aumente `MAX_CONNECTIONS` no código
2. Ou segmente em múltiplas salas

### "timeout ... idle timeout"
**Causa**: Conexão sem atividade por 60+ segundos.

**Ação**: Normal. Conexão será reestabelecida ao enviar/receber.

---

## Suporte

### Relatar Bugs
Abra issue no GitHub com:
- Versão (v0.2.0)
- Sistema operacional
- Log do erro
- Passos para reproduzir

### Perguntas
- GitHub Discussions
- Issue com label "question"

---

## Próxima Atualização (v0.3)

Planejado:
- ✅ **Compatibilidade retroativa** com v0.2
- GUI opcional (Electron)
- Histórico de mensagens
- Perfect Forward Secrecy

A partir da v0.3, planejamos manter compatibilidade retroativa sempre que possível.

---

**Última atualização**: 2025-10-17
**Versão deste guia**: v0.2.0
