// ============================================================================
// SENTINELA - Fonte: Have I Been Pwned (HIBP)
// ============================================================================
// 
// O Have I Been Pwned é a maior base de dados de vazamentos de credenciais,
// mantida pelo pesquisador de segurança Troy Hunt. O serviço permite verificar
// se um e-mail apareceu em vazamentos conhecidos.
//
// ABORDAGEM CORPORATIVA:
// Em vez de verificar e-mails individuais (que requer conhecimento prévio),
// esta implementação:
// 1. Gera padrões comuns de e-mail corporativo
// 2. Usa descoberta de e-mails via fontes públicas
// 3. Verifica cada e-mail descoberto no HIBP
//
// NOTA: API Enterprise do HIBP permite domain search, mas custa ~$1000/mês
// ============================================================================

import Bottleneck from 'bottleneck';
import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { http } from '../httpClient';
import { ResultadoFonte, AchadoCandidato } from '../../types';

// Rate limiter: HIBP permite ~1 requisição a cada 1.5 segundos
const limitador = new Bottleneck({ minTime: 1700, maxConcurrent: 1 });

interface BreachInfo {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  ModifiedDate: string;
  PwnCount: number;
  Description: string;
  LogoPath: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsFabricated: boolean;
  IsSensitive: boolean;
  IsRetired: boolean;
  IsSpamList: boolean;
}

// Padrões comuns de e-mail corporativo
const PADROES_EMAIL = [
  'contato',
  'comercial',
  'vendas',
  'financeiro',
  'rh',
  'juridico',
  'administrativo',
  'atendimento',
  'suporte',
  'sac',
  'marketing',
  'ti',
  'tecnologia',
  'diretoria',
  'presidencia',
  'gerencia',
  'compras',
  'faturamento',
  'cobranca',
  'info',
  'contabilidade',
  'admin',
  'webmaster',
  'postmaster',
  'noreply',
  'no-reply',
  'newsletter',
];

export async function verificarVazamentosEmail(email: string, chaveApi: string): Promise<ResultadoFonte> {
  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
  
  const executar = async (): Promise<{ breaches: BreachInfo[] }> => {
    const resposta = await http.get<BreachInfo[]>(url, {
      headers: {
        'hibp-api-key': chaveApi,
        'user-agent': 'Sentinela-ThreatIntel/1.0',
      },
    });
    
    if (!resposta.sucesso) {
      // 404 significa que o e-mail não está em nenhum vazamento
      if (resposta.erro?.codigoHttp === 404) {
        return { breaches: [] };
      }
      throw new Error(resposta.erro?.mensagem || 'Erro ao consultar HIBP');
    }
    
    return { breaches: resposta.dados || [] };
  };
  
  const { breaches } = await limitador.schedule(executar);
  
  if (breaches.length === 0) {
    return {
      achados: [],
      itensEncontrados: 0,
      metadados: { email, semVazamentos: true },
    };
  }
  
  const achados: AchadoCandidato[] = [];
  
  for (const breach of breaches) {
    // Determinar nível de risco baseado no tipo de dados vazados
    const classesDados = breach.DataClasses || [];
    
    const dadosCriticos = ['Passwords', 'Credit cards', 'Bank account numbers', 'Social security numbers'];
    
    // Vazamentos com dados críticos ou grandes = CRITICO, senão ALTO
    const isCritico = classesDados.some(d => dadosCriticos.includes(d)) || 
                      (breach.IsVerified && breach.PwnCount > 1000000);
    const nivelRisco = isCritico ? NivelRisco.CRITICO : NivelRisco.ALTO;
    
    // Traduzir classes de dados
    const dadosVazados = classesDados.map(traduzirClasseDados).join(', ');
    
    // Construir descrição
    let descricao = `O e-mail ${email} foi encontrado no vazamento "${breach.Title}" (${breach.Name}). `;
    descricao += `Este vazamento ocorreu em ${formatarData(breach.BreachDate)} e afetou ${breach.PwnCount.toLocaleString('pt-BR')} contas. `;
    
    if (dadosVazados) {
      descricao += `Tipos de dados expostos: ${dadosVazados}. `;
    }
    
    if (breach.IsSensitive) {
      descricao += `ATENÇÃO: Este é um vazamento marcado como sensível, o que pode indicar conteúdo adulto ou outras informações particularmente privadas. `;
    }
    
    // Construir recomendação
    let recomendacao = '';
    if (classesDados.includes('Passwords')) {
      recomendacao = 'URGENTE: A senha deste e-mail foi exposta. O usuário deve alterar imediatamente a senha deste e-mail E de qualquer outro serviço onde use a mesma senha. ';
      recomendacao += 'Recomenda-se habilitar autenticação em dois fatores (2FA) e utilizar um gerenciador de senhas.';
    } else {
      recomendacao = 'Embora senhas não tenham sido expostas neste vazamento específico, o usuário deve estar atento a tentativas de phishing direcionado. ';
      recomendacao += 'Considere habilitar autenticação em dois fatores (2FA) por precaução.';
    }
    
    achados.push({
      fonte: FonteInformacao.HIBP,
      nivelRisco,
      tipo: 'email_vazamento',
      tipoEntidade: TipoEntidade.EMAIL,
      entidade: email,
      titulo: `E-mail corporativo aparece no vazamento "${breach.Title}"`,
      descricao,
      recomendacao,
      evidencia: {
        email,
        nomeVazamento: breach.Name,
        tituloVazamento: breach.Title,
        dominioVazamento: breach.Domain,
        dataVazamento: breach.BreachDate,
        quantidadeAfetados: breach.PwnCount,
        verificado: breach.IsVerified,
        sensivel: breach.IsSensitive,
        classesDados,
        descricaoOriginal: breach.Description?.slice(0, 500),
      },
    });
  }
  
  return {
    achados,
    itensEncontrados: breaches.length,
    metadados: {
      email,
      totalVazamentos: breaches.length,
    },
  };
}

// Função para buscar e-mails corporativos comuns de um domínio
export async function descobrirEmailsCorporativos(dominio: string): Promise<string[]> {
  const emails: string[] = [];
  
  // Adicionar padrões comuns
  for (const padrao of PADROES_EMAIL) {
    emails.push(`${padrao}@${dominio}`);
  }
  
  return emails;
}

// Função principal que combina descoberta e verificação
export async function verificarVazamentosDominio(
  dominio: string, 
  chaveApi: string,
  emailsAdicionais?: string[]
): Promise<ResultadoFonte> {
  // Descobrir e-mails padrão
  const emailsPadrao = await descobrirEmailsCorporativos(dominio);
  
  // Combinar com e-mails adicionais fornecidos
  const todosEmails = [...new Set([...emailsPadrao, ...(emailsAdicionais || [])])];
  
  const achados: AchadoCandidato[] = [];
  let totalVazamentos = 0;
  const emailsComVazamento: string[] = [];
  const erros: string[] = [];
  
  // Verificar cada e-mail (com rate limiting automático)
  for (const email of todosEmails.slice(0, 30)) { // Limitar a 30 para não demorar muito
    try {
      const resultado = await verificarVazamentosEmail(email, chaveApi);
      
      if (resultado.achados.length > 0) {
        achados.push(...resultado.achados);
        emailsComVazamento.push(email);
        totalVazamentos += resultado.itensEncontrados;
      }
    } catch (erro: any) {
      // Se for rate limit, aguardar mais
      if (erro.message?.includes('rate')) {
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
      erros.push(`${email}: ${erro.message}`);
    }
  }
  
  // Se encontrou vazamentos, adicionar resumo
  if (emailsComVazamento.length > 0 && achados.length > 1) {
    achados.unshift({
      fonte: FonteInformacao.HIBP,
      nivelRisco: NivelRisco.ALTO,
      tipo: 'resumo_vazamentos',
      tipoEntidade: TipoEntidade.DOMINIO,
      entidade: dominio,
      titulo: `${emailsComVazamento.length} e-mail(s) do domínio encontrados em vazamentos`,
      descricao: `A verificação automática identificou ${emailsComVazamento.length} endereço(s) de e-mail do domínio ${dominio} em vazamentos públicos de dados. Os e-mails afetados são: ${emailsComVazamento.join(', ')}. Cada e-mail foi detalhado individualmente nos achados abaixo.`,
      recomendacao: 'Revise cada achado individual e tome as medidas recomendadas. Considere implementar uma política de rotação de senhas e habilitar autenticação em dois fatores para todos os usuários.',
      evidencia: {
        dominio,
        totalEmailsVerificados: todosEmails.length,
        emailsComVazamento,
        totalVazamentosEncontrados: totalVazamentos,
      },
    });
  }
  
  return {
    achados,
    itensEncontrados: totalVazamentos,
    metadados: {
      dominio,
      emailsVerificados: todosEmails.length,
      emailsComVazamento: emailsComVazamento.length,
      erros: erros.length > 0 ? erros.slice(0, 5) : undefined,
    },
  };
}

function traduzirClasseDados(classe: string): string {
  const traducoes: Record<string, string> = {
    'Passwords': 'Senhas',
    'Email addresses': 'Endereços de e-mail',
    'Usernames': 'Nomes de usuário',
    'Phone numbers': 'Números de telefone',
    'Physical addresses': 'Endereços físicos',
    'IP addresses': 'Endereços IP',
    'Dates of birth': 'Datas de nascimento',
    'Credit cards': 'Cartões de crédito',
    'Bank account numbers': 'Números de contas bancárias',
    'Social security numbers': 'CPF/Documentos',
    'Names': 'Nomes',
    'Genders': 'Gêneros',
    'Job titles': 'Cargos',
    'Employers': 'Empregadores',
    'Geographic locations': 'Localizações geográficas',
  };
  return traducoes[classe] || classe;
}

function formatarData(data: string): string {
  try {
    return new Date(data).toLocaleDateString('pt-BR');
  } catch {
    return data;
  }
}
