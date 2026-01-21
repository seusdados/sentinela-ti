// Sentinela TI - Script de inicialização para Railway
// Inicia o backend e serve o frontend

const { spawn } = require('child_process');
const express = require('express');
const path = require('path');
const fs = require('fs');
const { createProxyMiddleware } = require('http-proxy-middleware');

const PORT = process.env.PORT || 3000;
const BACKEND_PORT = 3001;

// Verificar se o diretório dist existe
const distPath = path.join(__dirname, 'frontend/dist');
console.log('Verificando diretório dist:', distPath);
console.log('Diretório existe:', fs.existsSync(distPath));
if (fs.existsSync(distPath)) {
  console.log('Conteúdo do dist:', fs.readdirSync(distPath));
}

// Iniciar o backend usando tsx (TypeScript executor)
console.log('Iniciando backend na porta', BACKEND_PORT);
const backend = spawn('npx', ['tsx', 'src/serverSimple.ts'], {
  cwd: path.join(__dirname, 'backend'),
  env: { ...process.env, PORT: BACKEND_PORT },
  stdio: 'inherit'
});

backend.on('error', (err) => {
  console.error('Erro ao iniciar backend:', err);
});

// Aguardar backend iniciar e então iniciar o frontend server
setTimeout(() => {
  const app = express();

  // Proxy para API backend
  app.use('/api', createProxyMiddleware({
    target: `http://localhost:${BACKEND_PORT}`,
    changeOrigin: true
  }));

  // Servir arquivos estáticos do frontend
  const staticPath = path.join(__dirname, 'frontend/dist');
  console.log('Servindo arquivos estáticos de:', staticPath);
  
  app.use(express.static(staticPath, {
    index: 'index.html',
    fallthrough: true
  }));

  // SPA fallback - servir index.html para todas as rotas não-API
  app.get('/{*path}', (req, res) => {
    const indexPath = path.join(staticPath, 'index.html');
    console.log('Fallback para:', indexPath);
    if (fs.existsSync(indexPath)) {
      res.sendFile(indexPath);
    } else {
      res.status(404).send('index.html não encontrado');
    }
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Sentinela TI rodando na porta ${PORT}`);
    console.log(`Frontend: http://localhost:${PORT}`);
    console.log(`Backend API: http://localhost:${BACKEND_PORT}`);
  });
}, 3000);

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Recebido SIGTERM, encerrando...');
  backend.kill();
  process.exit(0);
});
