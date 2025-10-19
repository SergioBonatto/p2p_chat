# Dockerfile para rodar p2p_chat em Alpine Linux
FROM node:18-alpine

# Instalar dependências de compilação para módulos nativos
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    gcc \
    git

WORKDIR /app

# Copiar arquivos de dependência
COPY package*.json ./

# Instalar dependências
RUN npm ci

# Copiar código fonte
COPY . .

# Compilar TypeScript
RUN npm run build

# Comando padrão
CMD ["npm", "run", "run"]
