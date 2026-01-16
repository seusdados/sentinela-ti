// ============================================================================
// SENTINELA - Worker de Processamento de Varreduras
// Execute com: npm run worker
// ============================================================================

import { Worker, Queue } from 'bullmq';
import { redis } from './config/redis';
import { executarVarredura } from './services/varreduraRunner';
import { gerarRelatorio } from './services/reports/relatorioService';
import { limparCacheExpirado } from './services/cacheService';

// Configuração das filas
const FILA_VARREDURAS = 'varreduras';
const FILA_RELATORIOS = 'relatorios';
const FILA_MANUTENCAO = 'manutencao';

// Criar filas
export const filaVarreduras = new Queue(FILA_VARREDURAS, { connection: redis });
export const filaRelatorios = new Queue(FILA_RELATORIOS, { connection: redis });
export const filaManutencao = new Queue(FILA_MANUTENCAO, { connection: redis });

// Worker de Varreduras
const workerVarreduras = new Worker(
  FILA_VARREDURAS,
  async (job) => {
    const { varreduraId } = job.data;
    console.log(`📡 Iniciando varredura ${varreduraId}`);
    
    try {
      await executarVarredura(varreduraId);
      console.log(`✅ Varredura ${varreduraId} concluída`);
      
      // Adicionar geração de relatório à fila
      await filaRelatorios.add('gerar', { varreduraId }, {
        delay: 5000, // Aguardar 5s para garantir que tudo foi persistido
      });
    } catch (erro: any) {
      console.error(`❌ Erro na varredura ${varreduraId}:`, erro.message);
      throw erro;
    }
  },
  {
    connection: redis,
    concurrency: 2, // Máximo 2 varreduras simultâneas
    limiter: {
      max: 5,
      duration: 60000, // Máximo 5 varreduras por minuto
    },
  }
);

// Worker de Relatórios
const workerRelatorios = new Worker(
  FILA_RELATORIOS,
  async (job) => {
    const { varreduraId } = job.data;
    console.log(`📄 Gerando relatório para varredura ${varreduraId}`);
    
    try {
      const caminho = await gerarRelatorio(varreduraId);
      console.log(`✅ Relatório gerado: ${caminho}`);
    } catch (erro: any) {
      console.error(`❌ Erro ao gerar relatório:`, erro.message);
      throw erro;
    }
  },
  {
    connection: redis,
    concurrency: 1,
  }
);

// Worker de Manutenção
const workerManutencao = new Worker(
  FILA_MANUTENCAO,
  async (job) => {
    const { tarefa } = job.data;
    console.log(`🔧 Executando tarefa de manutenção: ${tarefa}`);
    
    switch (tarefa) {
      case 'limpar_cache':
        const removidos = await limparCacheExpirado();
        console.log(`   ✅ ${removidos} registros de cache removidos`);
        break;
      default:
        console.log(`   ⚠️ Tarefa desconhecida: ${tarefa}`);
    }
  },
  {
    connection: redis,
    concurrency: 1,
  }
);

// Eventos dos workers
workerVarreduras.on('completed', (job) => {
  console.log(`✅ Job ${job.id} (varredura) concluído`);
});

workerVarreduras.on('failed', (job, err) => {
  console.error(`❌ Job ${job?.id} (varredura) falhou:`, err.message);
});

workerRelatorios.on('completed', (job) => {
  console.log(`✅ Job ${job.id} (relatório) concluído`);
});

workerRelatorios.on('failed', (job, err) => {
  console.error(`❌ Job ${job?.id} (relatório) falhou:`, err.message);
});

// Agendar limpeza de cache diária
async function agendarManutencao() {
  // Limpeza de cache a cada 6 horas
  await filaManutencao.add(
    'limpar_cache',
    { tarefa: 'limpar_cache' },
    {
      repeat: {
        every: 6 * 60 * 60 * 1000, // 6 horas
      },
    }
  );
  
  console.log('📅 Tarefas de manutenção agendadas');
}

// Inicialização
console.log('═══════════════════════════════════════════════════════════════');
console.log('');
console.log('   🛡️  SENTINELA - Worker de Processamento');
console.log('');
console.log('   Filas ativas:');
console.log('   • Varreduras (concurrency: 2)');
console.log('   • Relatórios (concurrency: 1)');
console.log('   • Manutenção (concurrency: 1)');
console.log('');
console.log('═══════════════════════════════════════════════════════════════');

agendarManutencao().catch(console.error);

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Encerrando workers...');
  await workerVarreduras.close();
  await workerRelatorios.close();
  await workerManutencao.close();
  process.exit(0);
});
