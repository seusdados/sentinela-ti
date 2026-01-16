# ============================================================================
# SENTINELA - Dockerfile Frontend
# Multi-stage build: Node para build, Nginx para servir
# ============================================================================

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Copiar arquivos de dependências
COPY package*.json ./

# Instalar dependências
RUN npm ci

# Copiar código fonte
COPY . .

# Build de produção
RUN npm run build

# Stage 2: Servidor Nginx
FROM nginx:alpine

# Remover configuração padrão
RUN rm -rf /usr/share/nginx/html/*

# Copiar build do React
COPY --from=builder /app/dist /usr/share/nginx/html

# Copiar configuração do Nginx
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expor porta
EXPOSE 80

# Comando
CMD ["nginx", "-g", "daemon off;"]
