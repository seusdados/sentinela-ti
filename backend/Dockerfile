# ============================================================================
# SENTINELA - Dockerfile Backend
# ============================================================================

FROM node:20-alpine

WORKDIR /app

# Instalar dependências de build
RUN apk add --no-cache python3 make g++ curl openssl

# Copiar arquivos de dependências
COPY package*.json ./
COPY prisma ./prisma/

# Instalar todas as dependências (incluindo dev para tsx)
RUN npm ci

# Gerar cliente Prisma
RUN npx prisma generate

# Copiar código fonte
COPY . .

# Criar diretório de relatórios
RUN mkdir -p /app/reports

# Expor porta
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3001/api/health || exit 1

# Comando padrão (usando tsx para executar TypeScript diretamente)
CMD ["npm", "run", "start:prod"]
