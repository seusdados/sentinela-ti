# Sentinela TI - Dockerfile para Railway
FROM node:22-alpine

WORKDIR /app

# Instalar tsx globalmente para executar TypeScript
RUN npm install -g tsx

# Copiar package.json primeiro para cache de dependências
COPY package*.json ./
COPY backend/package*.json ./backend/
COPY frontend/package*.json ./frontend/

# Instalar dependências raiz
RUN npm install --legacy-peer-deps

# Instalar dependências do backend
WORKDIR /app/backend
RUN npm install --legacy-peer-deps

# Instalar dependências do frontend
WORKDIR /app/frontend
RUN npm install --legacy-peer-deps

# Voltar para raiz e copiar código
WORKDIR /app
COPY . .

# Build do frontend
WORKDIR /app/frontend
RUN npm run build

# Voltar para raiz
WORKDIR /app

# Expor porta
EXPOSE 3000

# Comando de inicialização
CMD ["node", "start.js"]
