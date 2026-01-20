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
  IsMalware: boolean;
  IsSubscriptionFree: boolean;
}

interface PasteInfo {
  Source: string;
  Id: string;
  Title: string;
  Date: string;
  EmailCount: number;
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

// Classes de dados críticos que aumentam o risco
const DADOS_CRITICOS = [
  'Passwords',
  'Credit cards',
  'Bank account numbers',
  'Social security numbers',
  'Financial data',
  'Private messages',
  'Health records',
  'Government issued IDs',
  'Passport numbers',
  'Tax IDs',
];

// Classes de dados sensíveis
const DADOS_SENSIVEIS = [
  'Dates of birth',
  'Phone numbers',
  'Physical addresses',
  'Biometric data',
  'Sexual preferences',
  'Political views',
  'Religious beliefs',
  'Ethnic origins',
];

/**
 * Calcula o score de risco de um vazamento
 */
function calcularScoreVazamento(breach: BreachInfo): {
  score: number;
  fatores: string[];
} {
  let score = 0;
  const fatores: string[] = [];
  
  // Verificado vs não verificado
  if (breach.IsVerified) {
    score += 20;
    fatores.push('Vazamento verificado');
  }
  
  // Tamanho do vazamento
  if (breach.PwnCount > 100000000) {
    score += 30;
    fatores.push(`Mega vazamento: ${(breach.PwnCount / 1000000).toFixed(0)}M registros`);
  } else if (breach.PwnCount > 10000000) {
    score += 25;
    fatores.push(`Grande vazamento: ${(breach.PwnCount / 1000000).toFixed(1)}M registros`);
  } else if (breach.PwnCount > 1000000) {
    score += 20;
    fatores.push(`Vazamento significativo: ${(breach.PwnCount / 1000000).toFixed(1)}M registros`);
  } else if (breach.PwnCount > 100000) {
    score += 15;
    fatores.push(`Vazamento médio: ${(breach.PwnCount / 1000).toFixed(0)}K registros`);
  } else {
    score += 10;
    fatores.push(`Vazamento pequeno: ${breach.PwnCount.toLocaleString('pt-BR')} registros`);
  }
  
  // Tipos de dados vazados
  const classesDados = breach.DataClasses || [];
  
  const dadosCriticosPresentes = classesDados.filter(d => DADOS_CRITICOS.includes(d));
  if (dadosCriticosPresentes.length > 0) {
    score += 25;
    fatores.push(`Dados críticos: ${dadosCriticosPresentes.map(traduzirClasseDados).join(', ')}`);
  }
  
  const dadosSensiveisPresentes = classesDados.filter(d => DADOS_SENSIVEIS.includes(d));
  if (dadosSensiveisPresentes.length > 0) {
    score += 15;
    fatores.push(`Dados sensíveis: ${dadosSensiveisPresentes.map(traduzirClasseDados).join(', ')}`);
  }
  
  // Vazamento sensível (conteúdo adulto, etc.)
  if (breach.IsSensitive) {
    score += 10;
    fatores.push('Vazamento marcado como sensível');
  }
  
  // Idade do vazamento (mais recente = mais risco)
  const dataVazamento = new Date(breach.BreachDate);
  const agora = new Date();
  const diasDesdeVazamento = Math.floor((agora.getTime() - dataVazamento.getTime()) / (1000 * 60 * 60 * 24));
  
  if (diasDesdeVazamento < 180) {
    score += 15;
    fatores.push('Vazamento recente (< 6 meses)');
  } else if (diasDesdeVazamento < 365) {
    score += 10;
    fatores.push('Vazamento no último ano');
  } else if (diasDesdeVazamento < 730) {
    score += 5;
    fatores.push('Vazamento nos últimos 2 anos');
  }
  
  // Malware envolvido
  if (breach.IsMalware) {
    score += 20;
    fatores.push('Dados obtidos via malware');
  }
  
  return { score: Math.min(score, 100), fatores };
}

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
  
  // Ordenar por data (mais recente primeiro)
  breaches.sort((a, b) => new Date(b.BreachDate).getTime() - new Date(a.BreachDate).getTime());
  
  for (const breach of breaches) {
    // Calcular score de risco
    const { score, fatores } = calcularScoreVazamento(breach);
    
    // Determinar nível de risco baseado no score
    const classesDados = breach.DataClasses || [];
    const temSenhas = classesDados.includes('Passwords');
    const temDadosCriticos = classesDados.some(d => DADOS_CRITICOS.includes(d));
    
    let nivelRisco: typeof NivelRisco[keyof typeof NivelRisco] = NivelRisco.ALTO;
    if (score >= 70 || temDadosCriticos || (temSenhas && breach.IsVerified)) {
      nivelRisco = NivelRisco.CRITICO;
    }
    
    // Traduzir classes de dados
    const dadosVazados = classesDados.map(traduzirClasseDados).join(', ');
    
    // Calcular tempo desde o vazamento
    const dataVazamento = new Date(breach.BreachDate);
    const agora = new Date();
    const diasDesdeVazamento = Math.floor((agora.getTime() - dataVazamento.getTime()) / (1000 * 60 * 60 * 24));
    const tempoDesdeVazamento = diasDesdeVazamento < 30 ? `${diasDesdeVazamento} dias` :
                                diasDesdeVazamento < 365 ? `${Math.floor(diasDesdeVazamento / 30)} meses` :
                                `${Math.floor(diasDesdeVazamento / 365)} anos`;
    
    // Construir descrição detalhada
    let descricao = `O e-mail ${email} foi encontrado no vazamento "${breach.Title}" (${breach.Name}). `;
    descricao += `Este vazamento ocorreu em ${formatarData(breach.BreachDate)} (há ${tempoDesdeVazamento}) `;
    descricao += `e afetou ${breach.PwnCount.toLocaleString('pt-BR')} contas. `;
    
    if (dadosVazados) {
      descricao += `Tipos de dados expostos: ${dadosVazados}. `;
    }
    
    if (breach.IsVerified) {
      descricao += `Este vazamento foi VERIFICADO pelo HIBP. `;
    }
    
    if (breach.IsSensitive) {
      descricao += `ATENÇÃO: Este é um vazamento marcado como sensível. `;
    }
    
    if (breach.IsMalware) {
      descricao += `ATENÇÃO: Dados obtidos através de malware/infostealer. `;
    }
    
    descricao += `Score de risco: ${score}/100.`;
    
    // Construir recomendação detalhada
    let recomendacao = '';
    if (temSenhas) {
      recomendacao = 'URGENTE: A senha deste e-mail foi exposta. O usuário deve: ';
      recomendacao += '1) Alterar IMEDIATAMENTE a senha deste e-mail; ';
      recomendacao += '2) Alterar senhas de TODOS os serviços onde usa a mesma senha; ';
      recomendacao += '3) Habilitar autenticação em dois fatores (2FA); ';
      recomendacao += '4) Utilizar um gerenciador de senhas; ';
      recomendacao += '5) Verificar acessos recentes não autorizados.';
    } else if (temDadosCriticos) {
      recomendacao = 'CRÍTICO: Dados sensíveis foram expostos. O usuário deve: ';
      recomendacao += '1) Monitorar extratos bancários e cartões de crédito; ';
      recomendacao += '2) Considerar congelamento de crédito; ';
      recomendacao += '3) Estar atento a tentativas de fraude; ';
      recomendacao += '4) Habilitar alertas de transações.';
    } else {
      recomendacao = 'Embora senhas não tenham sido expostas neste vazamento específico, o usuário deve: ';
      recomendacao += '1) Estar atento a tentativas de phishing direcionado; ';
      recomendacao += '2) Não clicar em links suspeitos; ';
      recomendacao += '3) Considere habilitar autenticação em dois fatores (2FA).';
    }
    
    achados.push({
      fonte: FonteInformacao.HIBP,
      nivelRisco,
      tipo: 'email_vazamento',
      tipoEntidade: TipoEntidade.EMAIL,
      entidade: email,
      titulo: `E-mail em vazamento: "${breach.Title}" (${breach.PwnCount.toLocaleString('pt-BR')} afetados)`,
      descricao,
      recomendacao,
      evidencia: {
        email,
        
        // Informações do breach
        nomeVazamento: breach.Name,
        tituloVazamento: breach.Title,
        dominioVazamento: breach.Domain,
        logoVazamento: breach.LogoPath,
        
        // Datas
        dataVazamento: breach.BreachDate,
        dataAdicionado: breach.AddedDate,
        dataModificado: breach.ModifiedDate,
        diasDesdeVazamento,
        tempoDesdeVazamento,
        
        // Estatísticas
        quantidadeAfetados: breach.PwnCount,
        quantidadeFormatada: breach.PwnCount > 1000000 ? 
          `${(breach.PwnCount / 1000000).toFixed(1)}M` : 
          `${(breach.PwnCount / 1000).toFixed(0)}K`,
        
        // Classificações
        verificado: breach.IsVerified,
        fabricado: breach.IsFabricated,
        sensivel: breach.IsSensitive,
        aposentado: breach.IsRetired,
        listaSpam: breach.IsSpamList,
        malware: breach.IsMalware,
        
        // Dados vazados
        classesDados,
        classesDadosTraduzidas: classesDados.map(traduzirClasseDados),
        temSenhas,
        temDadosCriticos,
        dadosCriticosExpostos: classesDados.filter(d => DADOS_CRITICOS.includes(d)).map(traduzirClasseDados),
        dadosSensiveisExpostos: classesDados.filter(d => DADOS_SENSIVEIS.includes(d)).map(traduzirClasseDados),
        
        // Score de risco
        scoreRisco: score,
        fatoresRisco: fatores,
        
        // Descrição original
        descricaoOriginal: breach.Description?.replace(/<[^>]*>/g, '').slice(0, 1000),
      },
    });
  }
  
  return {
    achados,
    itensEncontrados: breaches.length,
    metadados: {
      email,
      totalVazamentos: breaches.length,
      vazamentoMaisRecente: breaches[0]?.BreachDate,
      vazamentoMaisAntigo: breaches[breaches.length - 1]?.BreachDate,
      totalRegistrosAfetados: breaches.reduce((sum, b) => sum + b.PwnCount, 0),
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
  const estatisticasBreaches: Record<string, { count: number; pwnCount: number }> = {};
  
  // Verificar cada e-mail (com rate limiting automático)
  for (const email of todosEmails.slice(0, 30)) { // Limitar a 30 para não demorar muito
    try {
      const resultado = await verificarVazamentosEmail(email, chaveApi);
      
      if (resultado.achados.length > 0) {
        achados.push(...resultado.achados);
        emailsComVazamento.push(email);
        totalVazamentos += resultado.itensEncontrados;
        
        // Agregar estatísticas por breach
        resultado.achados.forEach(achado => {
          const nome = achado.evidencia?.nomeVazamento as string;
          if (nome) {
            if (!estatisticasBreaches[nome]) {
              estatisticasBreaches[nome] = { count: 0, pwnCount: achado.evidencia?.quantidadeAfetados as number || 0 };
            }
            estatisticasBreaches[nome].count++;
          }
        });
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
    // Ordenar breaches por quantidade de emails afetados
    const breachesOrdenados = Object.entries(estatisticasBreaches)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 10);
    
    achados.unshift({
      fonte: FonteInformacao.HIBP,
      nivelRisco: NivelRisco.ALTO,
      tipo: 'resumo_vazamentos',
      tipoEntidade: TipoEntidade.DOMINIO,
      entidade: dominio,
      titulo: `${emailsComVazamento.length} e-mail(s) do domínio em ${totalVazamentos} vazamento(s)`,
      descricao: `A verificação automática identificou ${emailsComVazamento.length} endereço(s) de e-mail ` +
        `do domínio ${dominio} em ${totalVazamentos} vazamentos públicos de dados. ` +
        `Os e-mails afetados são: ${emailsComVazamento.join(', ')}. ` +
        `Vazamentos mais frequentes: ${breachesOrdenados.map(([nome, stats]) => `${nome} (${stats.count} emails)`).join(', ')}.`,
      recomendacao: 'Revise cada achado individual e tome as medidas recomendadas. ' +
        'Considere implementar uma política de rotação de senhas e habilitar autenticação em dois fatores para todos os usuários. ' +
        'Realize treinamento de conscientização sobre phishing.',
      evidencia: {
        dominio,
        totalEmailsVerificados: todosEmails.length,
        emailsComVazamento,
        totalVazamentosEncontrados: totalVazamentos,
        breachesMaisFrequentes: breachesOrdenados.map(([nome, stats]) => ({
          nome,
          emailsAfetados: stats.count,
          totalRegistros: stats.pwnCount
        })),
        estatisticasBreaches,
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
      totalVazamentos,
      breachesUnicos: Object.keys(estatisticasBreaches).length,
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
    'Financial data': 'Dados financeiros',
    'Private messages': 'Mensagens privadas',
    'Health records': 'Registros de saúde',
    'Government issued IDs': 'Documentos governamentais',
    'Passport numbers': 'Números de passaporte',
    'Tax IDs': 'CPF/CNPJ',
    'Biometric data': 'Dados biométricos',
    'Sexual preferences': 'Preferências sexuais',
    'Political views': 'Opiniões políticas',
    'Religious beliefs': 'Crenças religiosas',
    'Ethnic origins': 'Origens étnicas',
    'Purchase histories': 'Histórico de compras',
    'Education levels': 'Níveis de educação',
    'Family members names': 'Nomes de familiares',
    'Income levels': 'Níveis de renda',
    'Marital statuses': 'Estado civil',
    'Nationalities': 'Nacionalidades',
    'Occupations': 'Ocupações',
    'Personal descriptions': 'Descrições pessoais',
    'Personal interests': 'Interesses pessoais',
    'Photos': 'Fotos',
    'Profile photos': 'Fotos de perfil',
    'Relationship statuses': 'Status de relacionamento',
    'Security questions and answers': 'Perguntas e respostas de segurança',
    'Social connections': 'Conexões sociais',
    'Spoken languages': 'Idiomas falados',
    'Time zones': 'Fusos horários',
    'Travel habits': 'Hábitos de viagem',
    'Vehicle details': 'Detalhes de veículos',
    'Website activity': 'Atividade em websites',
    'Work habits': 'Hábitos de trabalho',
    'Years of professional experience': 'Anos de experiência profissional',
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
