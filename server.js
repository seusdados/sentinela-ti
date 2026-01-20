const express = require('express');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = 5900;

// Proxy para API backend
app.use('/api', createProxyMiddleware({
  target: 'http://localhost:3001',
  changeOrigin: true,
  pathRewrite: { '^/api': '/api' }
}));

// Servir arquivos estáticos do frontend
app.use(express.static(path.join(__dirname, 'frontend/dist')));

// SPA fallback - usar regex para Express 5
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend/dist/index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
