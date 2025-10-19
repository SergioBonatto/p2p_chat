#!/bin/bash
# Script para preparar release compilado para Alpine

set -e

echo "🔨 Compilando projeto..."
npm run build

echo "📦 Criando pacote de distribuição..."
mkdir -p release
cp -r dist release/
cp package.json release/
cp package-lock.json release/

# Criar package.json simplificado (apenas runtime dependencies)
cd release
cat > package.json << 'EOF'
{
  "name": "p2p_chat",
  "version": "0.2.0",
  "description": "Secure Terminal P2P chat",
  "main": "dist/index.js",
  "scripts": {
    "start": "node dist/index.js"
  },
  "dependencies": {
    "hyperswarm": "^4.14.2"
  }
}
EOF

echo "✅ Release criado em ./release/"
echo ""
echo "Para usar no Alpine:"
echo "1. Copie a pasta 'release' para o Alpine"
echo "2. cd release"
echo "3. npm install --production"
echo "4. npm start"
