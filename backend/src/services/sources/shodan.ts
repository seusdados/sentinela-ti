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

interface ShodanMatch {
  ip_str: string;
  port: number;
  transport?: string;
  product?: string;
  version?: string;
  org?: string;
  asn?: string;
  isp?: string;
  data?: string;
  hostnames?: string[];
  domains?: string[];
  vulns?: string[];
  tags?: string[];
  ssl?: {
    cert?: {
      subject?: { CN?: string; O?: string };
      issuer?: { CN?: string; O?: string };
      expires?: string;
      fingerprint?: { sha256?: string };
    };
    cipher?: { name?: string; version?: string };
    versions?: string[];
  };
  location?: {
    country_code?: string;
    country_name?: string;
    region_code?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
  };
  http?: {
    server?: string;
    title?: string;
    status?: number;
    redirects?: { location?: string }[];
  };
  _shodan?: {
    module?: string;
  };
}

interface ResultadoShodan {
  matches: ShodanMatch[];
  total: number;
}

interface ShodanHostInfo {
  ip_str: string;
  ports: number[];
  hostnames: string[];
  org: string;
  isp: string;
  asn: string;
  country_code: string;
  country_name: string;
  city: string;
  region_code: string;
  latitude: number;
  longitude: number;
  vulns?: string[];
  tags?: string[];
  data: ShodanMatch[];
}

export async function buscarInfraestrutura(dominio: string, chaveApi: string): Promise<ResultadoFonte> {
  const consulta = `hostname:${dominio}`;
  const url = `https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(chaveApi)}&query=${encodeURIComponent(consulta)}`;
  
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
  
  // Agrupar por IP para análise consolidada
  const porIP: Record<string, ShodanMatch[]> = {};
  matches.forEach(match => {
    if (!porIP[match.ip_str]) {
      porIP[match.ip_str] = [];
    }
    porIP[match.ip_str].push(match);
  });
  
  // Criar achado consolidado por IP
  Object.entries(porIP).forEach(([ip, servicos]) => {
    const portas = servicos.map(s => s.port).sort((a, b) => a - b);
    const produtos = [...new Set(servicos.map(s => s.product || s._shodan?.module).filter(Boolean))];
    const vulnerabilidades = [...new Set(servicos.flatMap(s => s.vulns || []))];
    const hostnames = [...new Set(servicos.flatMap(s => s.hostnames || []))];
    const location = servicos[0].location;
    const org = servicos[0].org;
    const asn = servicos[0].asn;
    const isp = servicos[0].isp;
    
    // Determinar nível de risco
    const temVulnerabilidades = vulnerabilidades.length > 0;
    const temServicosAltoRisco = servicos.some(s => isServicoAltoRisco(s.port, s.product || ''));
    
    // Usar apenas CRITICO ou ALTO para achados significativos
    const nivelRisco = temVulnerabilidades ? NivelRisco.CRITICO : NivelRisco.ALTO;
    const tipo = temVulnerabilidades ? 'vulnerabilidades_detectadas' : 
                 temServicosAltoRisco ? 'servicos_alto_risco' : 'infraestrutura_exposta';
    
    // Identificar serviços de alto risco
    const servicosAltoRisco = servicos.filter(s => isServicoAltoRisco(s.port, s.product || ''));
    const servicosComSSL = servicos.filter(s => s.ssl);
    
    // Verificar certificados SSL
    const certProblemas: string[] = [];
    servicosComSSL.forEach(s => {
      if (s.ssl?.cert?.expires) {
        const expiracao = new Date(s.ssl.cert.expires);
        const agora = new Date();
        const diasRestantes = Math.floor((expiracao.getTime() - agora.getTime()) / (1000 * 60 * 60 * 24));
        
        if (diasRestantes < 0) {
          certProblemas.push(`Certificado expirado na porta ${s.port}`);
        } else if (diasRestantes < 30) {
          certProblemas.push(`Certificado expira em ${diasRestantes} dias (porta ${s.port})`);
        }
      }
      
      // Verificar versões SSL/TLS inseguras
      if (s.ssl?.versions) {
        const versoesInseguras = s.ssl.versions.filter(v => 
          v.includes('SSLv2') || v.includes('SSLv3') || v.includes('TLSv1.0') || v.includes('TLSv1.1')
        );
        if (versoesInseguras.length > 0) {
          certProblemas.push(`Versões TLS inseguras na porta ${s.port}: ${versoesInseguras.join(', ')}`);
        }
      }
    });
    
    const descricao = `O IP ${ip} possui ${portas.length} porta(s) aberta(s): ${portas.join(', ')}. ` +
      `Serviços identificados: ${produtos.join(', ') || 'N/A'}. ` +
      `${vulnerabilidades.length > 0 ? `⚠️ ${vulnerabilidades.length} CVE(s) detectada(s). ` : ''}` +
      `${servicosAltoRisco.length > 0 ? `${servicosAltoRisco.length} serviço(s) de alto risco. ` : ''}` +
      `${certProblemas.length > 0 ? `Problemas de certificado: ${certProblemas.length}. ` : ''}` +
      `Localização: ${location?.city || 'N/A'}, ${location?.country_name || 'N/A'}.`;
    
    let recomendacao = '';
    if (vulnerabilidades.length > 0) {
      recomendacao = 'CRÍTICO: Aplique patches de segurança imediatamente para as CVEs detectadas. ';
    }
    if (servicosAltoRisco.length > 0) {
      recomendacao += 'Restrinja acesso aos serviços de alto risco por firewall ou VPN. ';
    }
    if (certProblemas.length > 0) {
      recomendacao += 'Renove certificados expirados e desabilite versões TLS inseguras. ';
    }
    if (!recomendacao) {
      recomendacao = 'Revise se todos os serviços expostos são necessários. Implemente monitoramento de segurança.';
    }
    
    achados.push({
      fonte: FonteInformacao.SHODAN,
      nivelRisco,
      tipo,
      tipoEntidade: TipoEntidade.IP,
      entidade: ip,
      titulo: `Infraestrutura Exposta: ${ip} (${portas.length} portas)`,
      descricao,
      recomendacao,
      evidencia: {
        ip,
        portasAbertas: portas,
        totalPortas: portas.length,
        servicos: servicos.map(s => ({
          porta: s.port,
          protocolo: s.transport || 'tcp',
          produto: s.product || s._shodan?.module,
          versao: s.version,
          banner: s.data ? s.data.substring(0, 300) : undefined,
          http: s.http ? {
            servidor: s.http.server,
            titulo: s.http.title,
            status: s.http.status,
          } : undefined,
          ssl: s.ssl ? {
            emissor: s.ssl.cert?.issuer?.O,
            expiracao: s.ssl.cert?.expires,
            versoes: s.ssl.versions,
            cipher: s.ssl.cipher?.name,
          } : undefined,
        })),
        vulnerabilidades: vulnerabilidades.slice(0, 20),
        totalCVEs: vulnerabilidades.length,
        hostnames,
        organizacao: org,
        asn,
        isp,
        geolocalizacao: location ? {
          pais: location.country_name,
          codigoPais: location.country_code,
          cidade: location.city,
          regiao: location.region_code,
          latitude: location.latitude,
          longitude: location.longitude,
        } : undefined,
        problemasSSL: certProblemas,
        servicosAltoRisco: servicosAltoRisco.map(s => ({
          porta: s.port,
          produto: s.product,
          motivo: getDescricaoServicoRisco(s.port, s.product || '', ip).desc.substring(0, 100),
        })),
      },
    });
  });
  
  // Adicionar achados individuais para vulnerabilidades críticas
  matches.forEach(match => {
    if (match.vulns && match.vulns.length > 0) {
      match.vulns.forEach(cve => {
        // Apenas CVEs críticas conhecidas
        const cveCriticas = ['CVE-2021-44228', 'CVE-2021-26855', 'CVE-2020-1472', 'CVE-2019-19781', 'CVE-2021-34473'];
        if (cveCriticas.some(c => cve.includes(c))) {
          achados.push({
            fonte: FonteInformacao.SHODAN,
            nivelRisco: NivelRisco.CRITICO,
            tipo: 'cve_critica',
            tipoEntidade: TipoEntidade.IP,
            entidade: match.ip_str,
            titulo: `CVE Crítica Detectada: ${cve}`,
            descricao: `A vulnerabilidade ${cve} foi detectada no serviço ${match.product || 'desconhecido'} ` +
              `na porta ${match.port} do IP ${match.ip_str}. Esta é uma vulnerabilidade de alto impacto ` +
              `frequentemente explorada por atacantes.`,
            recomendacao: 'URGENTE: Esta CVE é conhecida por ser ativamente explorada. ' +
              'Aplique o patch imediatamente ou isole o sistema afetado.',
            evidencia: {
              cve,
              ip: match.ip_str,
              porta: match.port,
              produto: match.product,
              versao: match.version,
            },
          });
        }
      });
    }
  });
  
  return {
    achados,
    itensEncontrados: matches.length,
    metadados: {
      total: resposta.dados.total,
      ipsUnicos: Object.keys(porIP).length,
      portasUnicas: [...new Set(matches.map(m => m.port))].length,
      totalCVEs: [...new Set(matches.flatMap(m => m.vulns || []))].length,
    },
  };
}

// Buscar informações detalhadas de um IP específico
export async function buscarDetalhesIP(ip: string, chaveApi: string): Promise<ShodanHostInfo | null> {
  try {
    const url = `https://api.shodan.io/shodan/host/${ip}?key=${encodeURIComponent(chaveApi)}`;
    const resposta = await http.get<ShodanHostInfo>(url);
    
    if (resposta.sucesso && resposta.dados) {
      return resposta.dados;
    }
    return null;
  } catch {
    return null;
  }
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
    1433,  // MSSQL
    5984,  // CouchDB
    9042,  // Cassandra
    2181,  // Zookeeper
    8080,  // HTTP alternativo (comum em apps vulneráveis)
  ];
  
  const produtosAltoRisco = [
    'mysql', 'postgresql', 'postgres', 'mongodb', 'redis',
    'elasticsearch', 'memcached', 'ftp', 'telnet', 'vnc',
    'mssql', 'couchdb', 'cassandra', 'zookeeper', 'jenkins',
    'phpmyadmin', 'adminer', 'webmin',
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
  
  if (produtoLower.includes('jenkins')) {
    return {
      desc: `O servidor Jenkins está exposto na internet (${ip}:${porta}). Jenkins exposto pode permitir execução de código arbitrário se não estiver devidamente protegido.`,
      rec: 'Configure autenticação forte, restrinja acesso por IP e mantenha o Jenkins atualizado. Revise permissões de jobs e scripts.',
    };
  }
  
  if (produtoLower.includes('phpmyadmin') || produtoLower.includes('adminer')) {
    return {
      desc: `Interface de administração de banco de dados exposta na internet (${ip}:${porta}). Ferramentas como phpMyAdmin são alvos frequentes de ataques automatizados.`,
      rec: 'URGENTE: Remova ou restrinja acesso a interfaces de administração. Utilize VPN ou autenticação adicional.',
    };
  }
  
  return {
    desc: `O serviço ${produto} está exposto na internet (${ip}:${porta}). Serviços expostos aumentam a superfície de ataque da organização.`,
    rec: 'Avalie se este serviço precisa estar exposto publicamente. Implemente autenticação, monitore logs de acesso e mantenha o software atualizado.',
  };
}
