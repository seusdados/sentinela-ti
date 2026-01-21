// Sentinela TI - Script de inicialização para Railway
// Agora o backend serve tanto a API quanto o frontend estático

const { spawn } = require('child_process');
const path = require('path');

// Railway define PORT via variável de ambiente
const PORT = process.env.PORT || 3000;
console.log('PORT do Railway:', PORT);

// Iniciar o backend usando tsx (TypeScript executor)
// O backend agora serve tanto a API quanto os arquivos estáticos do frontend
console.log('Iniciando servidor Sentinela...');
const backend = spawn('npx', ['tsx', 'src/serverSimple.ts'], {
  cwd: path.join(__dirname, 'backend'),
  env: { ...process.env },  // Passar todas as variáveis de ambiente, incluindo PORT
  stdio: 'inherit'
});

backend.on('error', (err) => {
  console.error('Erro ao iniciar servidor:', err);
  process.exit(1);
});

backend.on('exit', (code) => {
  console.log('Servidor encerrado com código:', code);
  process.exit(code || 0);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Recebido SIGTERM, encerrando...');
  backend.kill();
});

process.on('SIGINT', () => {
  console.log('Recebido SIGINT, encerrando...');
  backend.kill();
});
