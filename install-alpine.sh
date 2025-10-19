#!/bin/sh
# Script para configurar p2p_chat no Alpine Linux

set -e

echo "📦 Instalando dependências do sistema..."
apk add --no-cache python3 make g++ gcc git nodejs npm

echo "🧹 Limpando instalações anteriores..."
rm -rf node_modules package-lock.json dist

echo "📥 Instalando dependências do Node.js..."
npm install

echo "🔨 Compilando TypeScript..."
npm run build

echo "✅ Instalação concluída!"
echo ""
echo "Para iniciar o chat, execute:"
echo "  npm run run"
echo ""
echo "ou para desenvolvimento:"
echo "  npm start"
