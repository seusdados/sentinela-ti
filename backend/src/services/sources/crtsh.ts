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
  
  // Extrair subdomínios únicos
  const subdominios = new Set<string>();
  
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
        subdominios.add(nome);
      }
    }
  }
  
  const listaSubdominios = Array.from(subdominios).sort();
  
  // Identificar subdomínios potencialmente sensíveis
  const achados: AchadoCandidato[] = [];
  
  const padroesSensiveis = [
    { padrao: /^(dev|development|staging|stage|test|testing|uat|qa)\./i, tipo: 'ambiente_desenvolvimento', risco: NivelRisco.MEDIO },
    { padrao: /^(admin|administrator|cms|backend|backoffice|dashboard)\./i, tipo: 'painel_administrativo', risco: NivelRisco.ALTO },
    { padrao: /^(vpn|remote|rdp|ssh|bastion)\./i, tipo: 'acesso_remoto', risco: NivelRisco.ALTO },
    { padrao: /^(api|rest|graphql|ws|websocket)\./i, tipo: 'endpoint_api', risco: NivelRisco.MEDIO },
    { padrao: /^(db|database|mysql|postgres|mongo|redis|elastic)\./i, tipo: 'banco_dados', risco: NivelRisco.CRITICO },
    { padrao: /^(mail|smtp|imap|pop|webmail|exchange)\./i, tipo: 'servidor_email', risco: NivelRisco.MEDIO },
    { padrao: /^(ftp|sftp|upload|files|storage|cdn|assets)\./i, tipo: 'armazenamento', risco: NivelRisco.MEDIO },
    { padrao: /^(jenkins|gitlab|github|bitbucket|ci|cd|build)\./i, tipo: 'integracao_continua', risco: NivelRisco.ALTO },
    { padrao: /^(jira|confluence|wiki|docs|internal)\./i, tipo: 'ferramenta_interna', risco: NivelRisco.MEDIO },
    { padrao: /^(old|legacy|deprecated|backup|bkp)\./i, tipo: 'sistema_legado', risco: NivelRisco.ALTO },
  ];
  
  for (const subdominio of listaSubdominios) {
    for (const { padrao, tipo, risco } of padroesSensiveis) {
      if (padrao.test(subdominio)) {
        achados.push({
          fonte: FonteInformacao.CRTSH,
          nivelRisco: risco,
          tipo,
          tipoEntidade: TipoEntidade.SUBDOMINIO,
          entidade: subdominio,
          titulo: `Subdomínio potencialmente sensível descoberto: ${subdominio}`,
          descricao: gerarDescricao(tipo, subdominio),
          recomendacao: gerarRecomendacao(tipo),
          evidencia: {
            subdominio,
            tipoDetectado: tipo,
            totalSubdominiosEncontrados: listaSubdominios.length,
          },
        });
        break; // Apenas um achado por subdomínio
      }
    }
  }
  
  return {
    achados,
    itensEncontrados: listaSubdominios.length,
    metadados: {
      subdominios: listaSubdominios,
      totalCertificados: resposta.dados.length,
    },
  };
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
  };
  
  return recomendacoes[tipo] || 'Avalie a necessidade de exposição deste subdomínio e implemente controles de acesso adequados.';
}
