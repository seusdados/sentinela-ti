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
  cpe?: string[];
  org?: string;
  asn?: string;
  isp?: string;
  data?: string;
  hostnames?: string[];
  domains?: string[];
  vulns?: Record<string, {
    cvss?: number;
    references?: string[];
    summary?: string;
    verified?: boolean;
  }>;
  tags?: string[];
  ssl?: {
    cert?: {
      subject?: { CN?: string; O?: string };
      issuer?: { CN?: string; O?: string };
      expires?: string;
      fingerprint?: { sha256?: string };
      serial?: number;
    };
    cipher?: { name?: string; version?: string; bits?: number };
    versions?: string[];
    chain?: string[];
  };
  location?: {
    country_code?: string;
    country_name?: string;
    region_code?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    postal_code?: string;
  };
  http?: {
    server?: string;
    title?: string;
    status?: number;
    redirects?: { location?: string }[];
    host?: string;
    html_hash?: number;
    robots_hash?: number;
    sitemap_hash?: number;
    waf?: string;
  };
  _shodan?: {
    module?: string;
    crawler?: string;
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

// Base de dados de CVEs conhecidas com CVSS scores
const CVE_DATABASE: Record<string, { cvss: number; severity: string; description: string; exploited: boolean }> = {
  'CVE-2021-44228': { cvss: 10.0, severity: 'CRITICAL', description: 'Log4Shell - Apache Log4j RCE', exploited: true },
  'CVE-2021-45046': { cvss: 9.0, severity: 'CRITICAL', description: 'Log4j DoS/RCE', exploited: true },
  'CVE-2021-26855': { cvss: 9.8, severity: 'CRITICAL', description: 'ProxyLogon - Exchange Server RCE', exploited: true },
  'CVE-2021-27065': { cvss: 7.8, severity: 'HIGH', description: 'Exchange Server Post-Auth RCE', exploited: true },
  'CVE-2020-1472': { cvss: 10.0, severity: 'CRITICAL', description: 'Zerologon - Netlogon Privilege Escalation', exploited: true },
  'CVE-2019-19781': { cvss: 9.8, severity: 'CRITICAL', description: 'Citrix ADC/Gateway RCE', exploited: true },
  'CVE-2021-34473': { cvss: 9.8, severity: 'CRITICAL', description: 'ProxyShell - Exchange Server RCE', exploited: true },
  'CVE-2021-34523': { cvss: 9.8, severity: 'CRITICAL', description: 'ProxyShell - Exchange Privilege Escalation', exploited: true },
  'CVE-2021-31207': { cvss: 7.2, severity: 'HIGH', description: 'ProxyShell - Exchange Security Bypass', exploited: true },
  'CVE-2021-26084': { cvss: 9.8, severity: 'CRITICAL', description: 'Confluence Server OGNL Injection', exploited: true },
  'CVE-2022-22965': { cvss: 9.8, severity: 'CRITICAL', description: 'Spring4Shell - Spring Framework RCE', exploited: true },
  'CVE-2022-26134': { cvss: 9.8, severity: 'CRITICAL', description: 'Confluence Server OGNL Injection', exploited: true },
  'CVE-2023-34362': { cvss: 9.8, severity: 'CRITICAL', description: 'MOVEit Transfer SQL Injection', exploited: true },
  'CVE-2023-0669': { cvss: 7.2, severity: 'HIGH', description: 'GoAnywhere MFT RCE', exploited: true },
  'CVE-2023-27350': { cvss: 9.8, severity: 'CRITICAL', description: 'PaperCut MF/NG RCE', exploited: true },
  'CVE-2023-4966': { cvss: 9.4, severity: 'CRITICAL', description: 'Citrix Bleed - Session Hijacking', exploited: true },
  'CVE-2024-3400': { cvss: 10.0, severity: 'CRITICAL', description: 'PAN-OS GlobalProtect RCE', exploited: true },
  'CVE-2019-0708': { cvss: 9.8, severity: 'CRITICAL', description: 'BlueKeep - RDP RCE', exploited: true },
  'CVE-2017-0144': { cvss: 8.1, severity: 'HIGH', description: 'EternalBlue - SMB RCE (WannaCry)', exploited: true },
  'CVE-2020-0796': { cvss: 10.0, severity: 'CRITICAL', description: 'SMBGhost - SMBv3 RCE', exploited: true },
};

/**
 * Obtém informações detalhadas de uma CVE
 */
function getCVEInfo(cve: string): { cvss: number; severity: string; description: string; exploited: boolean } | null {
  // Primeiro verifica na base local
  if (CVE_DATABASE[cve]) {
    return CVE_DATABASE[cve];
  }
  
  // Tenta extrair CVSS do padrão CVE-YYYY-NNNNN
  const match = cve.match(/CVE-(\d{4})-(\d+)/);
  if (match) {
    const year = parseInt(match[1]);
    // CVEs mais recentes tendem a ser mais críticas se detectadas pelo Shodan
    const estimatedCvss = year >= 2022 ? 8.0 : year >= 2020 ? 7.0 : 6.0;
    return {
      cvss: estimatedCvss,
      severity: estimatedCvss >= 9.0 ? 'CRITICAL' : estimatedCvss >= 7.0 ? 'HIGH' : 'MEDIUM',
      description: `Vulnerabilidade ${cve} detectada`,
      exploited: false
    };
  }
  
  return null;
}

/**
 * Classifica o nível de risco baseado no CVSS
 */
function cvssToNivelRisco(cvss: number): NivelRisco {
  if (cvss >= 9.0) return NivelRisco.CRITICO;
  if (cvss >= 7.0) return NivelRisco.ALTO;
  if (cvss >= 4.0) return NivelRisco.MEDIO;
  return NivelRisco.BAIXO;
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
    const hostnames = [...new Set(servicos.flatMap(s => s.hostnames || []))];
    const location = servicos[0].location;
    const org = servicos[0].org;
    const asn = servicos[0].asn;
    const isp = servicos[0].isp;
    
    // Processar vulnerabilidades com detalhes de CVSS
    const vulnerabilidadesDetalhadas: Array<{
      cve: string;
      cvss: number;
      severity: string;
      description: string;
      exploited: boolean;
      porta: number;
      produto?: string;
      versao?: string;
    }> = [];
    
    servicos.forEach(s => {
      if (s.vulns) {
        Object.entries(s.vulns).forEach(([cve, info]) => {
          const cveInfo = getCVEInfo(cve);
          vulnerabilidadesDetalhadas.push({
            cve,
            cvss: info.cvss || cveInfo?.cvss || 5.0,
            severity: cveInfo?.severity || (info.cvss && info.cvss >= 9.0 ? 'CRITICAL' : 'HIGH'),
            description: info.summary || cveInfo?.description || 'Vulnerabilidade detectada',
            exploited: cveInfo?.exploited || false,
            porta: s.port,
            produto: s.product,
            versao: s.version
          });
        });
      }
    });
    
    // Ordenar por CVSS (mais críticas primeiro)
    vulnerabilidadesDetalhadas.sort((a, b) => b.cvss - a.cvss);
    
    // Determinar nível de risco
    const temVulnerabilidades = vulnerabilidadesDetalhadas.length > 0;
    const temVulnCritica = vulnerabilidadesDetalhadas.some(v => v.cvss >= 9.0);
    const temVulnExplorada = vulnerabilidadesDetalhadas.some(v => v.exploited);
    const temServicosAltoRisco = servicos.some(s => isServicoAltoRisco(s.port, s.product || ''));
    
    // Usar apenas CRITICO ou ALTO para achados significativos
    let nivelRisco = NivelRisco.ALTO;
    if (temVulnCritica || temVulnExplorada) {
      nivelRisco = NivelRisco.CRITICO;
    } else if (temVulnerabilidades) {
      nivelRisco = vulnerabilidadesDetalhadas[0].cvss >= 7.0 ? NivelRisco.CRITICO : NivelRisco.ALTO;
    }
    
    const tipo = temVulnerabilidades ? 'vulnerabilidades_detectadas' : 
                 temServicosAltoRisco ? 'servicos_alto_risco' : 'infraestrutura_exposta';
    
    // Identificar serviços de alto risco
    const servicosAltoRisco = servicos.filter(s => isServicoAltoRisco(s.port, s.product || ''));
    const servicosComSSL = servicos.filter(s => s.ssl);
    
    // Verificar certificados SSL
    const certProblemas: string[] = [];
    const certDetalhes: Array<{
      porta: number;
      emissor: string;
      expiracao: string;
      diasRestantes: number;
      versoes: string[];
      cipher: string;
      bits: number;
      problemas: string[];
    }> = [];
    
    servicosComSSL.forEach(s => {
      const problemas: string[] = [];
      let diasRestantes = 999;
      
      if (s.ssl?.cert?.expires) {
        const expiracao = new Date(s.ssl.cert.expires);
        const agora = new Date();
        diasRestantes = Math.floor((expiracao.getTime() - agora.getTime()) / (1000 * 60 * 60 * 24));
        
        if (diasRestantes < 0) {
          problemas.push('Certificado expirado');
          certProblemas.push(`Certificado expirado na porta ${s.port}`);
        } else if (diasRestantes < 30) {
          problemas.push(`Expira em ${diasRestantes} dias`);
          certProblemas.push(`Certificado expira em ${diasRestantes} dias (porta ${s.port})`);
        }
      }
      
      // Verificar versões SSL/TLS inseguras
      if (s.ssl?.versions) {
        const versoesInseguras = s.ssl.versions.filter(v => 
          v.includes('SSLv2') || v.includes('SSLv3') || v.includes('TLSv1.0') || v.includes('TLSv1.1')
        );
        if (versoesInseguras.length > 0) {
          problemas.push(`TLS inseguro: ${versoesInseguras.join(', ')}`);
          certProblemas.push(`Versões TLS inseguras na porta ${s.port}: ${versoesInseguras.join(', ')}`);
        }
      }
      
      // Verificar cipher fraco
      if (s.ssl?.cipher?.bits && s.ssl.cipher.bits < 128) {
        problemas.push(`Cipher fraco: ${s.ssl.cipher.bits} bits`);
      }
      
      certDetalhes.push({
        porta: s.port,
        emissor: s.ssl?.cert?.issuer?.O || 'Desconhecido',
        expiracao: s.ssl?.cert?.expires || 'N/A',
        diasRestantes,
        versoes: s.ssl?.versions || [],
        cipher: s.ssl?.cipher?.name || 'N/A',
        bits: s.ssl?.cipher?.bits || 0,
        problemas
      });
    });
    
    // Construir descrição detalhada
    const descricao = `O IP ${ip} possui ${portas.length} porta(s) aberta(s): ${portas.join(', ')}. ` +
      `Serviços identificados: ${produtos.join(', ') || 'N/A'}. ` +
      `${vulnerabilidadesDetalhadas.length > 0 ? 
        `⚠️ ${vulnerabilidadesDetalhadas.length} CVE(s) detectada(s), ` +
        `${vulnerabilidadesDetalhadas.filter(v => v.cvss >= 9.0).length} crítica(s), ` +
        `${vulnerabilidadesDetalhadas.filter(v => v.exploited).length} ativamente explorada(s). ` : ''}` +
      `${servicosAltoRisco.length > 0 ? `${servicosAltoRisco.length} serviço(s) de alto risco. ` : ''}` +
      `${certProblemas.length > 0 ? `Problemas de certificado: ${certProblemas.length}. ` : ''}` +
      `Localização: ${location?.city || 'N/A'}, ${location?.country_name || 'N/A'} (${org || 'N/A'}).`;
    
    let recomendacao = '';
    if (temVulnExplorada) {
      recomendacao = 'URGENTE: CVEs ativamente exploradas detectadas. Aplique patches IMEDIATAMENTE ou isole os sistemas. ';
    } else if (temVulnCritica) {
      recomendacao = 'CRÍTICO: Aplique patches de segurança imediatamente para as CVEs críticas detectadas. ';
    } else if (vulnerabilidadesDetalhadas.length > 0) {
      recomendacao = 'Aplique patches de segurança para as vulnerabilidades detectadas. ';
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
      titulo: `Infraestrutura Exposta: ${ip} (${portas.length} portas${vulnerabilidadesDetalhadas.length > 0 ? `, ${vulnerabilidadesDetalhadas.length} CVEs` : ''})`,
      descricao,
      recomendacao,
      evidencia: {
        ip,
        
        // Portas e serviços
        portasAbertas: portas,
        totalPortas: portas.length,
        servicos: servicos.map(s => ({
          porta: s.port,
          protocolo: s.transport || 'tcp',
          produto: s.product || s._shodan?.module,
          versao: s.version,
          cpe: s.cpe,
          banner: s.data ? s.data.substring(0, 500) : undefined,
          http: s.http ? {
            servidor: s.http.server,
            titulo: s.http.title,
            status: s.http.status,
            waf: s.http.waf,
          } : undefined,
        })),
        
        // Vulnerabilidades com CVSS
        vulnerabilidades: vulnerabilidadesDetalhadas.slice(0, 30),
        totalCVEs: vulnerabilidadesDetalhadas.length,
        cvesExploradas: vulnerabilidadesDetalhadas.filter(v => v.exploited).map(v => v.cve),
        cvesCriticas: vulnerabilidadesDetalhadas.filter(v => v.cvss >= 9.0).map(v => ({
          cve: v.cve,
          cvss: v.cvss,
          description: v.description
        })),
        cvssMaximo: vulnerabilidadesDetalhadas.length > 0 ? vulnerabilidadesDetalhadas[0].cvss : 0,
        
        // SSL/TLS
        certificados: certDetalhes,
        problemasSSL: certProblemas,
        
        // Geolocalização
        hostnames,
        organizacao: org,
        asn,
        isp,
        geolocalizacao: location ? {
          pais: location.country_name,
          codigoPais: location.country_code,
          cidade: location.city,
          regiao: location.region_code,
          codigoPostal: location.postal_code,
          latitude: location.latitude,
          longitude: location.longitude,
        } : undefined,
        
        // Serviços de alto risco
        servicosAltoRisco: servicosAltoRisco.map(s => ({
          porta: s.port,
          produto: s.product,
          versao: s.version,
          motivo: getDescricaoServicoRisco(s.port, s.product || '', ip).desc.substring(0, 150),
        })),
      },
    });
  });
  
  // Adicionar achados individuais para vulnerabilidades críticas exploradas
  matches.forEach(match => {
    if (match.vulns) {
      Object.entries(match.vulns).forEach(([cve, info]) => {
        const cveInfo = getCVEInfo(cve);
        if (cveInfo?.exploited || (info.cvss && info.cvss >= 9.5)) {
          achados.push({
            fonte: FonteInformacao.SHODAN,
            nivelRisco: NivelRisco.CRITICO,
            tipo: 'cve_critica_explorada',
            tipoEntidade: TipoEntidade.IP,
            entidade: match.ip_str,
            titulo: `🚨 CVE Ativamente Explorada: ${cve} (CVSS ${cveInfo?.cvss || info.cvss || 'N/A'})`,
            descricao: `A vulnerabilidade ${cve} foi detectada no serviço ${match.product || 'desconhecido'} ` +
              `versão ${match.version || 'N/A'} na porta ${match.port} do IP ${match.ip_str}. ` +
              `${cveInfo?.description || info.summary || 'Esta é uma vulnerabilidade de alto impacto'}. ` +
              `${cveInfo?.exploited ? 'ATENÇÃO: Esta CVE é conhecida por ser ATIVAMENTE EXPLORADA por atacantes.' : ''}`,
            recomendacao: 'URGENTE: Esta CVE é conhecida por ser ativamente explorada. ' +
              'Aplique o patch imediatamente ou isole o sistema afetado. ' +
              'Verifique logs para sinais de comprometimento.',
            evidencia: {
              cve,
              cvss: cveInfo?.cvss || info.cvss,
              severity: cveInfo?.severity,
              description: cveInfo?.description || info.summary,
              exploited: cveInfo?.exploited,
              references: info.references,
              ip: match.ip_str,
              porta: match.port,
              produto: match.product,
              versao: match.version,
              cpe: match.cpe,
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
      totalCVEs: [...new Set(matches.flatMap(m => Object.keys(m.vulns || {})))].length,
      cvesExploradas: matches.flatMap(m => 
        Object.keys(m.vulns || {}).filter(cve => getCVEInfo(cve)?.exploited)
      ).length,
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
    445,   // SMB
    139,   // NetBIOS
    1521,  // Oracle
    5601,  // Kibana
    9000,  // SonarQube/PHP-FPM
    8443,  // HTTPS alternativo
  ];
  
  const produtosAltoRisco = [
    'mysql', 'postgresql', 'postgres', 'mongodb', 'redis',
    'elasticsearch', 'memcached', 'ftp', 'telnet', 'vnc',
    'mssql', 'couchdb', 'cassandra', 'zookeeper', 'jenkins',
    'phpmyadmin', 'adminer', 'webmin', 'kibana', 'grafana',
    'sonarqube', 'gitlab', 'jira', 'confluence', 'bitbucket',
    'oracle', 'smb', 'netbios', 'rdp', 'remote desktop',
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
  
  if (porta === 3389 || produtoLower.includes('rdp') || produtoLower.includes('remote desktop')) {
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
  
  if (porta === 445 || porta === 139 || produtoLower.includes('smb')) {
    return {
      desc: `O serviço SMB/CIFS está exposto na internet (${ip}:${porta}). SMB exposto é extremamente perigoso e foi usado em ataques como WannaCry e NotPetya.`,
      rec: 'URGENTE: SMB nunca deve estar exposto na internet. Bloqueie as portas 445 e 139 no firewall de borda imediatamente.',
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
