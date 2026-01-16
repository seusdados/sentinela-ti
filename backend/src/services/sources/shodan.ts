// ============================================================================
// SENTINELA - Fonte: Shodan (Motor de Busca de Dispositivos)
// ============================================================================
// 
// O Shodan é um motor de busca que varre a internet identificando dispositivos
// e serviços conectados. Diferente do Google que indexa páginas web, o Shodan
// indexa banners de serviços (como servidores web, bancos de dados, câmeras IP).
//
// UTILIDADE: Descobrir serviços expostos da empresa na internet:
// - Servidores web e suas versões (Apache, Nginx, IIS)
// - Bancos de dados expostos (MySQL, MongoDB, Redis)
// - Dispositivos IoT e câmeras
// - Serviços com vulnerabilidades conhecidas
// ============================================================================

import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { http } from '../httpClient';
import { ResultadoFonte, AchadoCandidato } from '../../types';

interface ResultadoShodan {
  matches: {
    ip_str: string;
    port: number;
    transport?: string;
    product?: string;
    version?: string;
    org?: string;
    asn?: string;
    data?: string;
    hostnames?: string[];
    vulns?: string[];
    _shodan?: {
      module?: string;
    };
  }[];
  total: number;
}

export async function buscarInfraestrutura(dominio: string, chaveApi: string): Promise<ResultadoFonte> {
  const consulta = `hostname:${dominio}`;
  const url = `https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(chaveApi)}&query=${encodeURIComponent(consulta)}&minify=true`;
  
  const resposta = await http.get<ResultadoShodan>(url);
  
  if (!resposta.sucesso) {
    throw new Error(resposta.erro?.mensagem || 'Erro ao consultar Shodan');
  }
  
  if (!resposta.dados?.matches) {
    return {
      achados: [],
      itensEncontrados: 0,
      metadados: { total: 0 },
    };
  }
  
  const achados: AchadoCandidato[] = [];
  const matches = resposta.dados.matches;
  
  for (const match of matches) {
    const ip = match.ip_str;
    const porta = match.port;
    const produto = match.product || match._shodan?.module || 'serviço desconhecido';
    const versao = match.version;
    const hostnames = match.hostnames || [];
    const vulnerabilidades = match.vulns || [];
    
    // Determinar nível de risco baseado no tipo de serviço e vulnerabilidades
    let nivelRisco = NivelRisco.BAIXO;
    let tipo = 'servico_exposto';
    let titulo = `Serviço exposto: ${produto}${versao ? ` ${versao}` : ''} (${ip}:${porta})`;
    let descricao = '';
    let recomendacao = '';
    
    // Verificar vulnerabilidades conhecidas
    if (vulnerabilidades.length > 0) {
      nivelRisco = NivelRisco.CRITICO;
      tipo = 'vulnerabilidade_conhecida';
      titulo = `CRÍTICO: Serviço com vulnerabilidades conhecidas (${ip}:${porta})`;
      descricao = `O serviço ${produto} na porta ${porta} possui ${vulnerabilidades.length} vulnerabilidade(s) conhecida(s): ${vulnerabilidades.slice(0, 5).join(', ')}${vulnerabilidades.length > 5 ? '...' : ''}. Vulnerabilidades conhecidas podem ser exploradas por atacantes usando ferramentas automatizadas.`;
      recomendacao = 'URGENTE: Atualize o software para a versão mais recente e aplique os patches de segurança disponíveis. Se a atualização não for possível, considere restringir o acesso a este serviço.';
    }
    // Portas e serviços de alto risco
    else if (isServicoAltoRisco(porta, produto)) {
      nivelRisco = NivelRisco.ALTO;
      tipo = 'servico_alto_risco';
      const { desc, rec } = getDescricaoServicoRisco(porta, produto, ip);
      descricao = desc;
      recomendacao = rec;
    }
    // Serviços comuns
    else {
      nivelRisco = NivelRisco.MEDIO;
      descricao = `O servidor ${ip} está executando ${produto}${versao ? ` versão ${versao}` : ''} na porta ${porta}. Este serviço está acessível publicamente na internet.`;
      recomendacao = 'Verifique se este serviço precisa estar exposto publicamente. Se possível, restrinja o acesso por firewall ou implemente autenticação adicional.';
    }
    
    achados.push({
      fonte: FonteInformacao.SHODAN,
      nivelRisco,
      tipo,
      tipoEntidade: TipoEntidade.IP,
      entidade: ip,
      titulo,
      descricao,
      recomendacao,
      evidencia: {
        ip,
        porta,
        transporte: match.transport,
        produto,
        versao,
        organizacao: match.org,
        asn: match.asn,
        hostnames,
        vulnerabilidades: vulnerabilidades.slice(0, 10),
        bannerResumido: match.data ? match.data.slice(0, 500) : undefined,
      },
    });
  }
  
  return {
    achados,
    itensEncontrados: matches.length,
    metadados: {
      total: resposta.dados.total,
      ipsUnicos: [...new Set(matches.map(m => m.ip_str))].length,
    },
  };
}

function isServicoAltoRisco(porta: number, produto: string): boolean {
  const portasAltoRisco = [
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    3306,  // MySQL
    5432,  // PostgreSQL
    6379,  // Redis
    27017, // MongoDB
    9200,  // Elasticsearch
    11211, // Memcached
    3389,  // RDP
    5900,  // VNC
  ];
  
  const produtosAltoRisco = [
    'mysql', 'postgresql', 'postgres', 'mongodb', 'redis',
    'elasticsearch', 'memcached', 'ftp', 'telnet', 'vnc',
  ];
  
  const produtoLower = produto.toLowerCase();
  
  return portasAltoRisco.includes(porta) || 
         produtosAltoRisco.some(p => produtoLower.includes(p));
}

function getDescricaoServicoRisco(porta: number, produto: string, ip: string): { desc: string; rec: string } {
  const produtoLower = produto.toLowerCase();
  
  if (produtoLower.includes('mysql') || porta === 3306) {
    return {
      desc: `O banco de dados MySQL está exposto diretamente na internet (${ip}:${porta}). Bancos de dados expostos são alvos prioritários para atacantes, que podem tentar ataques de força bruta ou explorar vulnerabilidades para acessar dados sensíveis.`,
      rec: 'URGENTE: Bancos de dados nunca devem estar expostos diretamente na internet. Configure o firewall para permitir conexões apenas de IPs autorizados e utilize túneis SSH ou VPN para acesso remoto.',
    };
  }
  
  if (produtoLower.includes('mongo') || porta === 27017) {
    return {
      desc: `O banco de dados MongoDB está exposto na internet (${ip}:${porta}). MongoDB sem autenticação habilitada é uma das causas mais comuns de vazamentos de dados massivos.`,
      rec: 'URGENTE: Habilite autenticação no MongoDB, restrinja o bind address e configure firewall para bloquear acesso externo.',
    };
  }
  
  if (produtoLower.includes('redis') || porta === 6379) {
    return {
      desc: `O servidor Redis está exposto na internet (${ip}:${porta}). Redis sem senha pode permitir execução de comandos arbitrários e acesso completo aos dados em cache.`,
      rec: 'URGENTE: Configure senha no Redis (requirepass), desabilite comandos perigosos e restrinja acesso por firewall.',
    };
  }
  
  if (produtoLower.includes('elastic') || porta === 9200) {
    return {
      desc: `O Elasticsearch está exposto na internet (${ip}:${porta}). Clusters Elasticsearch abertos podem expor grandes volumes de dados indexados.`,
      rec: 'Configure autenticação X-Pack, restrinja acesso por firewall e revise as permissões de índices.',
    };
  }
  
  if (porta === 22) {
    return {
      desc: `O servidor SSH está exposto na internet (${ip}:${porta}). Embora SSH seja geralmente seguro, servidores expostos são constantemente alvo de ataques de força bruta.`,
      rec: 'Desabilite autenticação por senha e utilize apenas chaves SSH. Considere usar fail2ban ou similar para bloquear tentativas de brute force. Se possível, restrinja acesso por IP.',
    };
  }
  
  if (porta === 23 || produtoLower.includes('telnet')) {
    return {
      desc: `O serviço Telnet está exposto na internet (${ip}:${porta}). Telnet transmite dados sem criptografia, incluindo senhas, e é considerado inseguro.`,
      rec: 'URGENTE: Desabilite o Telnet imediatamente e utilize SSH como alternativa segura.',
    };
  }
  
  if (porta === 3389 || produtoLower.includes('rdp')) {
    return {
      desc: `O serviço de Área de Trabalho Remota (RDP) está exposto na internet (${ip}:${porta}). RDP exposto é um dos vetores mais explorados por ransomware e outros malwares.`,
      rec: 'URGENTE: Nunca exponha RDP diretamente na internet. Utilize VPN ou Azure AD Application Proxy. Implemente Network Level Authentication (NLA) e MFA.',
    };
  }
  
  if (porta === 21 || produtoLower.includes('ftp')) {
    return {
      desc: `O servidor FTP está exposto na internet (${ip}:${porta}). FTP tradicional transmite credenciais em texto claro e pode permitir acesso anônimo se mal configurado.`,
      rec: 'Migre para SFTP (SSH File Transfer Protocol) ou FTPS. Se FTP for necessário, desabilite acesso anônimo e utilize credenciais fortes.',
    };
  }
  
  return {
    desc: `O serviço ${produto} está exposto na internet (${ip}:${porta}). Serviços expostos aumentam a superfície de ataque da organização.`,
    rec: 'Avalie se este serviço precisa estar exposto publicamente. Implemente autenticação, monitore logs de acesso e mantenha o software atualizado.',
  };
}
