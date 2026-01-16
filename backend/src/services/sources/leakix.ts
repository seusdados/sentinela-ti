// ============================================================================
// SENTINELA - Fonte: LeakIX (Detecção de Vazamentos e Configurações Expostas)
// ============================================================================
// 
// O LeakIX é uma plataforma especializada em detectar configurações incorretas
// e vazamentos de dados na internet. Ele identifica bancos de dados abertos,
// arquivos de configuração expostos e outros dados sensíveis acessíveis.
//
// UTILIDADE: Identificar exposições de dados da empresa:
// - Bancos de dados sem autenticação
// - Arquivos de configuração (.env, config.json)
// - Backups expostos
// - Diretórios abertos
// ============================================================================

import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { http } from '../httpClient';
import { ResultadoFonte, AchadoCandidato } from '../../types';

interface ResultadoLeakIX {
  host?: string;
  ip?: string;
  ip_str?: string;
  port?: number;
  proto?: string;
  summary?: string;
  severity?: string;
  tags?: string[];
  geoip?: {
    country_name?: string;
    city_name?: string;
  };
  service?: {
    software?: string;
    name?: string;
    protocol?: string;
  };
  leak?: {
    type?: string;
    severity?: string;
    dataset?: {
      rows?: number;
      files?: number;
      size?: number;
    };
  };
}

export async function buscarVazamentos(dominio: string, chaveApi: string): Promise<ResultadoFonte> {
  // Busca por host exato e subdomínios
  const consulta = `host:"${dominio}" OR host:"*.${dominio}"`;
  const url = `https://leakix.net/api/search?q=${encodeURIComponent(consulta)}&scope=services`;
  
  const resposta = await http.get<ResultadoLeakIX[] | { data: ResultadoLeakIX[] }>(url, {
    headers: { 'api-key': chaveApi },
  });
  
  if (!resposta.sucesso) {
    throw new Error(resposta.erro?.mensagem || 'Erro ao consultar LeakIX');
  }
  
  // LeakIX pode retornar array direto ou objeto com propriedade data
  const dados = Array.isArray(resposta.dados) 
    ? resposta.dados 
    : resposta.dados?.data || [];
  
  if (!Array.isArray(dados) || dados.length === 0) {
    return {
      achados: [],
      itensEncontrados: 0,
      metadados: { total: 0 },
    };
  }
  
  const achados: AchadoCandidato[] = [];
  
  for (const item of dados) {
    const host = String(item.host || '').toLowerCase();
    const ip = String(item.ip || item.ip_str || '').trim();
    const porta = item.port ? Number(item.port) : undefined;
    const protocolo = item.proto || item.service?.protocol || '';
    const resumo = item.summary || item.service?.software || item.service?.name || '';
    const severidade = item.severity || item.leak?.severity;
    const tags = item.tags || [];
    const leak = item.leak;
    
    if (!host && !ip) continue;
    
    const entidade = host || ip;
    
    // Determinar nível de risco baseado na severidade e tipo de vazamento
    let nivelRisco = NivelRisco.ALTO;
    let tipo = 'servico_exposto';
    let titulo = '';
    let descricao = '';
    let recomendacao = '';
    
    // Verificar se é um vazamento de dados
    if (leak?.type || tags.some(t => t.toLowerCase().includes('leak'))) {
      nivelRisco = NivelRisco.CRITICO;
      tipo = 'vazamento_dados';
      
      const tamanhoDataset = leak?.dataset;
      let detalhesVazamento = '';
      
      if (tamanhoDataset?.rows) {
        detalhesVazamento = `aproximadamente ${tamanhoDataset.rows.toLocaleString('pt-BR')} registros`;
      } else if (tamanhoDataset?.files) {
        detalhesVazamento = `${tamanhoDataset.files.toLocaleString('pt-BR')} arquivos`;
      } else if (tamanhoDataset?.size) {
        detalhesVazamento = `${formatarTamanho(tamanhoDataset.size)} de dados`;
      }
      
      titulo = `CRÍTICO: Possível vazamento de dados detectado em ${entidade}`;
      descricao = `O LeakIX identificou uma exposição de dados no host ${entidade}${porta ? `:${porta}` : ''}. ${detalhesVazamento ? `O vazamento contém ${detalhesVazamento}.` : ''} ${resumo ? `Tipo detectado: ${resumo}.` : ''} Dados expostos podem incluir informações sensíveis de clientes, credenciais ou dados corporativos.`;
      recomendacao = 'URGENTE: Investigue imediatamente esta exposição. Identifique quais dados foram expostos, corrija a configuração e avalie a necessidade de notificação à ANPD conforme a LGPD.';
    }
    // Banco de dados exposto
    else if (tags.some(t => ['mongodb', 'elasticsearch', 'redis', 'mysql', 'postgresql'].includes(t.toLowerCase()))) {
      nivelRisco = NivelRisco.CRITICO;
      tipo = 'banco_dados_exposto';
      titulo = `CRÍTICO: Banco de dados exposto em ${entidade}`;
      descricao = `Um banco de dados (${resumo || 'tipo não identificado'}) foi encontrado exposto em ${entidade}${porta ? `:${porta}` : ''}. Bancos de dados expostos são uma das principais causas de vazamentos massivos de dados.`;
      recomendacao = 'URGENTE: Remova o acesso público ao banco de dados imediatamente. Configure firewall, habilite autenticação e revise os dados que podem ter sido acessados.';
    }
    // Configuração exposta
    else if (tags.some(t => ['config', 'env', 'backup', 'git'].includes(t.toLowerCase()))) {
      nivelRisco = NivelRisco.ALTO;
      tipo = 'configuracao_exposta';
      titulo = `Arquivo de configuração exposto em ${entidade}`;
      descricao = `Um arquivo de configuração ou backup foi encontrado acessível em ${entidade}${porta ? `:${porta}` : ''}. ${resumo ? `Detalhes: ${resumo}.` : ''} Arquivos de configuração frequentemente contêm credenciais, chaves de API e outras informações sensíveis.`;
      recomendacao = 'Remova imediatamente o acesso público a estes arquivos. Altere todas as credenciais que possam estar expostas e revise as configurações do servidor web.';
    }
    // Serviço genérico exposto
    else {
      titulo = `Serviço potencialmente exposto detectado em ${entidade}`;
      descricao = `O LeakIX identificou um serviço exposto em ${entidade}${porta ? `:${porta}` : ''}. ${resumo ? `Serviço: ${resumo}.` : ''} ${protocolo ? `Protocolo: ${protocolo}.` : ''}`;
      recomendacao = 'Verifique se este serviço precisa estar exposto publicamente e implemente controles de acesso adequados.';
    }
    
    achados.push({
      fonte: FonteInformacao.LEAKIX,
      nivelRisco,
      tipo,
      tipoEntidade: host ? TipoEntidade.SUBDOMINIO : TipoEntidade.IP,
      entidade,
      titulo,
      descricao,
      recomendacao,
      evidencia: {
        host,
        ip,
        porta,
        protocolo,
        resumo,
        tags,
        localizacao: item.geoip ? `${item.geoip.city_name || ''}, ${item.geoip.country_name || ''}`.trim() : undefined,
        dadosVazamento: leak,
      },
    });
  }
  
  return {
    achados,
    itensEncontrados: dados.length,
    metadados: { total: dados.length },
  };
}

function formatarTamanho(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}
