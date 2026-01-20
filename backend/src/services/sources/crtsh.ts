// ============================================================================
// SENTINELA - Fonte: crt.sh (Transparência de Certificados SSL)
// ============================================================================
// 
// O crt.sh é um serviço gratuito que monitora a emissão de certificados SSL.
// Quando uma empresa emite um certificado para um domínio ou subdomínio,
// essa informação fica publicamente disponível.
//
// UTILIDADE: Descobrir todos os subdomínios de uma empresa, revelando:
// - Ambientes de desenvolvimento expostos (dev.empresa.com)
// - Sistemas internos acessíveis (vpn.empresa.com, admin.empresa.com)
// - Serviços esquecidos ou não documentados
// ============================================================================

import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { http } from '../httpClient';
import { ResultadoFonte, AchadoCandidato } from '../../types';

interface RegistroCertificado {
  id: number;
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  entry_timestamp: string;
  not_before: string;
  not_after: string;
  serial_number: string;
}

interface CertificadoProcessado {
  subdominio: string;
  emissor: string;
  dataEmissao: string;
  dataExpiracao: string;
  serialNumber: string;
  expirado: boolean;
  diasParaExpirar: number;
}

export async function descobrirSubdominios(dominio: string): Promise<ResultadoFonte> {
  // Busca certificados emitidos para o domínio e todos os subdomínios
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(dominio)}&output=json`;
  
  const resposta = await http.get<RegistroCertificado[]>(url);
  
  if (!resposta.sucesso || !resposta.dados) {
    return {
      achados: [],
      itensEncontrados: 0,
      metadados: { erro: resposta.erro?.mensagem },
    };
  }
  
  // Processar certificados
  const certificadosPorSubdominio: Record<string, CertificadoProcessado[]> = {};
  const agora = new Date();
  
  for (const registro of resposta.dados) {
    const valor = registro.name_value;
    if (typeof valor !== 'string') continue;
    
    // O campo name_value pode conter múltiplos domínios separados por quebra de linha
    for (const linha of valor.split('\n')) {
      const nome = linha.trim().toLowerCase();
      
      // Ignorar wildcards e domínios vazios
      if (!nome || nome.includes('*')) continue;
      
      // Verificar se é um subdomínio válido do domínio alvo
      if (nome === dominio || nome.endsWith(`.${dominio}`)) {
        const dataExpiracao = new Date(registro.not_after);
        const diasParaExpirar = Math.floor((dataExpiracao.getTime() - agora.getTime()) / (1000 * 60 * 60 * 24));
        
        const certProcessado: CertificadoProcessado = {
          subdominio: nome,
          emissor: extrairEmissor(registro.issuer_name),
          dataEmissao: registro.not_before,
          dataExpiracao: registro.not_after,
          serialNumber: registro.serial_number,
          expirado: diasParaExpirar < 0,
          diasParaExpirar,
        };
        
        if (!certificadosPorSubdominio[nome]) {
          certificadosPorSubdominio[nome] = [];
        }
        certificadosPorSubdominio[nome].push(certProcessado);
      }
    }
  }
  
  const listaSubdominios = Object.keys(certificadosPorSubdominio).sort();
  
  // Identificar subdomínios potencialmente sensíveis
  const achados: AchadoCandidato[] = [];
  
  const padroesSensiveis = [
    { padrao: /^(dev|development|staging|stage|test|testing|uat|qa|sandbox|demo)\./i, tipo: 'ambiente_desenvolvimento', risco: NivelRisco.MEDIO },
    { padrao: /^(admin|administrator|cms|backend|backoffice|dashboard|panel|control|manage)\./i, tipo: 'painel_administrativo', risco: NivelRisco.ALTO },
    { padrao: /^(vpn|remote|rdp|ssh|bastion|jump|gateway)\./i, tipo: 'acesso_remoto', risco: NivelRisco.ALTO },
    { padrao: /^(api|rest|graphql|ws|websocket|v1|v2|v3)\./i, tipo: 'endpoint_api', risco: NivelRisco.MEDIO },
    { padrao: /^(db|database|mysql|postgres|mongo|redis|elastic|sql|data)\./i, tipo: 'banco_dados', risco: NivelRisco.CRITICO },
    { padrao: /^(mail|smtp|imap|pop|webmail|exchange|mx|email)\./i, tipo: 'servidor_email', risco: NivelRisco.MEDIO },
    { padrao: /^(ftp|sftp|upload|files|storage|cdn|assets|media|static)\./i, tipo: 'armazenamento', risco: NivelRisco.MEDIO },
    { padrao: /^(jenkins|gitlab|github|bitbucket|ci|cd|build|deploy|docker|k8s|kubernetes)\./i, tipo: 'integracao_continua', risco: NivelRisco.ALTO },
    { padrao: /^(jira|confluence|wiki|docs|internal|intranet|corp|corporate)\./i, tipo: 'ferramenta_interna', risco: NivelRisco.MEDIO },
    { padrao: /^(old|legacy|deprecated|backup|bkp|archive|temp|tmp)\./i, tipo: 'sistema_legado', risco: NivelRisco.ALTO },
    { padrao: /^(payment|pay|checkout|billing|invoice|finance)\./i, tipo: 'sistema_pagamento', risco: NivelRisco.CRITICO },
    { padrao: /^(auth|login|sso|oauth|identity|iam)\./i, tipo: 'autenticacao', risco: NivelRisco.ALTO },
    { padrao: /^(monitor|grafana|prometheus|kibana|logs|metrics|status)\./i, tipo: 'monitoramento', risco: NivelRisco.MEDIO },
  ];
  
  for (const subdominio of listaSubdominios) {
    const certs = certificadosPorSubdominio[subdominio];
    const certMaisRecente = certs.reduce((a, b) => 
      new Date(a.dataEmissao) > new Date(b.dataEmissao) ? a : b
    );
    
    // Verificar certificados expirados
    const certsExpirados = certs.filter(c => c.expirado);
    const certsProximosExpirar = certs.filter(c => !c.expirado && c.diasParaExpirar <= 30);
    
    if (certsExpirados.length > 0 && certsExpirados.length === certs.length) {
      achados.push({
        fonte: FonteInformacao.CRTSH,
        nivelRisco: NivelRisco.MEDIO,
        tipo: 'certificado_expirado',
        tipoEntidade: TipoEntidade.SUBDOMINIO,
        entidade: subdominio,
        titulo: `Certificado SSL Expirado: ${subdominio}`,
        descricao: `O subdomínio "${subdominio}" possui apenas certificados expirados. ` +
          `Último certificado expirou em ${certMaisRecente.dataExpiracao}. ` +
          `Emissor: ${certMaisRecente.emissor}.`,
        recomendacao: 'Renove o certificado SSL ou desative o subdomínio se não estiver mais em uso.',
        evidencia: {
          subdominio,
          emissor: certMaisRecente.emissor,
          dataExpiracao: certMaisRecente.dataExpiracao,
          diasExpirado: Math.abs(certMaisRecente.diasParaExpirar),
          totalCertificados: certs.length,
        },
      });
    } else if (certsProximosExpirar.length > 0) {
      const certProximo = certsProximosExpirar[0];
      achados.push({
        fonte: FonteInformacao.CRTSH,
        nivelRisco: NivelRisco.BAIXO,
        tipo: 'certificado_expirando',
        tipoEntidade: TipoEntidade.SUBDOMINIO,
        entidade: subdominio,
        titulo: `Certificado SSL Expirando em Breve: ${subdominio}`,
        descricao: `O certificado do subdomínio "${subdominio}" expira em ${certProximo.diasParaExpirar} dias ` +
          `(${certProximo.dataExpiracao}). Emissor: ${certProximo.emissor}.`,
        recomendacao: 'Renove o certificado SSL antes da data de expiração para evitar interrupções.',
        evidencia: {
          subdominio,
          emissor: certProximo.emissor,
          dataExpiracao: certProximo.dataExpiracao,
          diasParaExpirar: certProximo.diasParaExpirar,
        },
      });
    }
    
    // Verificar padrões sensíveis
    for (const { padrao, tipo, risco } of padroesSensiveis) {
      if (padrao.test(subdominio)) {
        achados.push({
          fonte: FonteInformacao.CRTSH,
          nivelRisco: risco,
          tipo,
          tipoEntidade: TipoEntidade.SUBDOMINIO,
          entidade: subdominio,
          titulo: `Subdomínio Potencialmente Sensível: ${subdominio}`,
          descricao: gerarDescricao(tipo, subdominio),
          recomendacao: gerarRecomendacao(tipo),
          evidencia: {
            subdominio,
            tipoDetectado: tipo,
            emissor: certMaisRecente.emissor,
            dataEmissao: certMaisRecente.dataEmissao,
            dataExpiracao: certMaisRecente.dataExpiracao,
            algoritmo: extrairAlgoritmo(certMaisRecente.emissor),
            totalCertificados: certs.length,
            totalSubdominiosEncontrados: listaSubdominios.length,
          },
        });
        break; // Apenas um achado por subdomínio
      }
    }
  }
  
  // Estatísticas de emissores
  const emissoresCont: Record<string, number> = {};
  Object.values(certificadosPorSubdominio).flat().forEach(cert => {
    emissoresCont[cert.emissor] = (emissoresCont[cert.emissor] || 0) + 1;
  });
  
  const topEmissores = Object.entries(emissoresCont)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([emissor, count]) => ({ emissor, count }));
  
  return {
    achados,
    itensEncontrados: listaSubdominios.length,
    metadados: {
      subdominios: listaSubdominios,
      totalCertificados: resposta.dados.length,
      totalSubdominios: listaSubdominios.length,
      certificadosExpirados: Object.values(certificadosPorSubdominio)
        .flat()
        .filter(c => c.expirado).length,
      certificadosProximosExpirar: Object.values(certificadosPorSubdominio)
        .flat()
        .filter(c => !c.expirado && c.diasParaExpirar <= 30).length,
      topEmissores,
      subdominiosPorTipo: {
        desenvolvimento: listaSubdominios.filter(s => /^(dev|staging|test|qa)/i.test(s)).length,
        administrativo: listaSubdominios.filter(s => /^(admin|backend|dashboard)/i.test(s)).length,
        api: listaSubdominios.filter(s => /^(api|rest|graphql)/i.test(s)).length,
        outros: listaSubdominios.length,
      },
    },
  };
}

function extrairEmissor(issuerName: string): string {
  // Extrair o nome legível do emissor
  const match = issuerName.match(/O=([^,]+)/);
  if (match) return match[1].trim();
  
  const cnMatch = issuerName.match(/CN=([^,]+)/);
  if (cnMatch) return cnMatch[1].trim();
  
  return issuerName.substring(0, 50);
}

function extrairAlgoritmo(issuerName: string): string {
  if (issuerName.toLowerCase().includes('ecdsa')) return 'ECDSA';
  if (issuerName.toLowerCase().includes('rsa')) return 'RSA';
  return 'Desconhecido';
}

function gerarDescricao(tipo: string, subdominio: string): string {
  const descricoes: Record<string, string> = {
    ambiente_desenvolvimento: `O subdomínio "${subdominio}" sugere um ambiente de desenvolvimento ou homologação. Estes ambientes frequentemente possuem menos proteções de segurança e podem expor funcionalidades em teste ou dados de teste que incluem informações reais.`,
    painel_administrativo: `O subdomínio "${subdominio}" indica a presença de um painel administrativo. Painéis de administração são alvos prioritários para atacantes pois fornecem acesso privilegiado aos sistemas.`,
    acesso_remoto: `O subdomínio "${subdominio}" sugere um ponto de acesso remoto à rede. Serviços de acesso remoto são vetores comuns de invasão quando mal configurados ou com credenciais fracas.`,
    endpoint_api: `O subdomínio "${subdominio}" indica um endpoint de API. APIs expostas podem revelar estruturas de dados, permitir enumeração de recursos ou conter vulnerabilidades de autorização.`,
    banco_dados: `O subdomínio "${subdominio}" sugere um servidor de banco de dados exposto. Bancos de dados nunca devem ser acessíveis diretamente pela internet.`,
    servidor_email: `O subdomínio "${subdominio}" indica um servidor de e-mail. Servidores de e-mail expostos podem ser usados para ataques de phishing ou spam.`,
    armazenamento: `O subdomínio "${subdominio}" sugere um serviço de armazenamento de arquivos. Estes serviços podem conter documentos sensíveis se mal configurados.`,
    integracao_continua: `O subdomínio "${subdominio}" indica uma ferramenta de integração contínua. Estas ferramentas frequentemente contêm credenciais e acesso ao código-fonte.`,
    ferramenta_interna: `O subdomínio "${subdominio}" sugere uma ferramenta interna da empresa. Ferramentas internas podem conter informações confidenciais sobre projetos e operações.`,
    sistema_legado: `O subdomínio "${subdominio}" indica um sistema legado ou backup. Sistemas antigos frequentemente não recebem atualizações de segurança e podem conter vulnerabilidades conhecidas.`,
    sistema_pagamento: `O subdomínio "${subdominio}" indica um sistema de pagamentos. Sistemas financeiros são alvos de alto valor e requerem proteção máxima.`,
    autenticacao: `O subdomínio "${subdominio}" indica um sistema de autenticação. Comprometimento deste sistema pode dar acesso a todos os outros sistemas.`,
    monitoramento: `O subdomínio "${subdominio}" indica ferramentas de monitoramento. Estas podem revelar informações sobre a infraestrutura interna.`,
  };
  
  return descricoes[tipo] || `O subdomínio "${subdominio}" foi identificado como potencialmente sensível.`;
}

function gerarRecomendacao(tipo: string): string {
  const recomendacoes: Record<string, string> = {
    ambiente_desenvolvimento: 'Verifique se este ambiente está protegido por autenticação e não contém dados reais de produção. Considere restringir o acesso por IP ou VPN.',
    painel_administrativo: 'Implemente autenticação multifator (MFA), restrinja o acesso por IP e monitore tentativas de login suspeitas.',
    acesso_remoto: 'Verifique se o serviço está atualizado, utilize autenticação forte e considere implementar uma solução de VPN corporativa.',
    endpoint_api: 'Revise a documentação da API, implemente rate limiting, autenticação adequada e não exponha endpoints de debug em produção.',
    banco_dados: 'URGENTE: Bancos de dados nunca devem ser expostos diretamente à internet. Configure firewall para permitir acesso apenas de IPs autorizados.',
    servidor_email: 'Verifique as configurações de SPF, DKIM e DMARC. Implemente filtros anti-spam e monitore tentativas de abuso.',
    armazenamento: 'Revise as permissões de acesso aos arquivos. Implemente autenticação e considere restringir uploads a tipos de arquivo seguros.',
    integracao_continua: 'Restrinja o acesso por IP/VPN, revise as credenciais armazenadas e implemente autenticação forte.',
    ferramenta_interna: 'Verifique se o acesso está restrito a funcionários autorizados e se a ferramenta não expõe informações sensíveis.',
    sistema_legado: 'Avalie a necessidade de manter este sistema. Se necessário, aplique atualizações de segurança ou isole-o da rede pública.',
    sistema_pagamento: 'CRÍTICO: Garanta conformidade com PCI-DSS. Implemente WAF, monitoramento contínuo e testes de penetração regulares.',
    autenticacao: 'Implemente MFA obrigatório, monitore tentativas de login e considere soluções de detecção de fraude.',
    monitoramento: 'Restrinja acesso às ferramentas de monitoramento por VPN. Não exponha métricas sensíveis publicamente.',
  };
  
  return recomendacoes[tipo] || 'Avalie a necessidade de exposição deste subdomínio e implemente controles de acesso adequados.';
}
