// Sentinela TI - Script de inicialização para Railway
// Inicia o backend e serve o frontend

const { spawn } = require('child_process');
const express = require('express');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');

const PORT = process.env.PORT || 3000;
const BACKEND_PORT = 3001;

// Iniciar o backend
console.log('Iniciando backend na porta', BACKEND_PORT);
const backend = spawn('node', ['dist/serverSimple.js'], {
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
  app.use(express.static(path.join(__dirname, 'frontend/dist')));

  // SPA fallback
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/dist/index.html'));
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
