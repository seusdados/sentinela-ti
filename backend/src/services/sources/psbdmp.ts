// ============================================================================
// SENTINELA - Fonte: PSBDMP (Indexador de Pastes e Dumps)
// ============================================================================
// 
// O PSBDMP é um serviço que indexa conteúdo publicado em sites como Pastebin,
// GitHub Gists e outros repositórios de texto. Atacantes frequentemente
// publicam dados vazados, credenciais e informações sensíveis nesses sites.
//
// UTILIDADE: Detectar exposições em pastes públicos:
// - Credenciais vazadas
// - Configurações expostas
// - Dados de clientes publicados
// - Informações internas da empresa
// ============================================================================

import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { http } from '../httpClient';
import { ResultadoFonte, AchadoCandidato } from '../../types';

interface ResultadoPSBDMP {
  data?: {
    id: string;
    tags?: string[];
    length?: number;
    time?: string;
    text?: string;
  }[];
  count?: number;
}

export async function buscarEmPastes(termo: string): Promise<ResultadoFonte> {
  const url = `https://psbdmp.ws/api/v3/dump/search/${encodeURIComponent(termo)}`;
  
  const resposta = await http.get<ResultadoPSBDMP>(url);
  
  if (!resposta.sucesso) {
    throw new Error(resposta.erro?.mensagem || 'Erro ao consultar PSBDMP');
  }
  
  const dados = resposta.dados?.data || [];
  const achados: AchadoCandidato[] = [];
  
  if (dados.length > 0) {
    // Analisar os pastes encontrados
    const pastesComSenhas = dados.filter(p => 
      p.tags?.some(t => ['password', 'credential', 'leak', 'dump'].includes(t.toLowerCase())) ||
      p.text?.toLowerCase().includes('password') ||
      p.text?.toLowerCase().includes('senha')
    );
    
    const pastesComEmails = dados.filter(p =>
      p.text?.includes('@') ||
      p.tags?.some(t => ['email', 'mail'].includes(t.toLowerCase()))
    );
    
    const pastesComConfigs = dados.filter(p =>
      p.tags?.some(t => ['config', 'env', 'api', 'key', 'secret'].includes(t.toLowerCase())) ||
      p.text?.toLowerCase().includes('api_key') ||
      p.text?.toLowerCase().includes('secret')
    );
    
    // Determinar nível de risco
    let nivelRisco = NivelRisco.MEDIO;
    let tipo = 'mencao_paste';
    let titulo = '';
    let descricao = '';
    let recomendacao = '';
    
    if (pastesComSenhas.length > 0) {
      nivelRisco = NivelRisco.CRITICO;
      tipo = 'credenciais_expostas';
      titulo = `CRÍTICO: Possíveis credenciais expostas em ${pastesComSenhas.length} paste(s)`;
      descricao = `Foram encontradas ${pastesComSenhas.length} publicações em sites de paste que mencionam "${termo}" e parecem conter credenciais ou senhas. `;
      descricao += `Ao todo, ${dados.length} paste(s) mencionam o termo buscado. `;
      descricao += `Pastes com credenciais expostas são frequentemente resultado de vazamentos de dados ou phishing bem-sucedido.`;
      recomendacao = 'URGENTE: Analise os pastes identificados para determinar quais credenciais foram expostas. Force a troca de senha de todas as contas potencialmente comprometidas. Verifique logs de acesso para identificar uso não autorizado.';
    } else if (pastesComConfigs.length > 0) {
      nivelRisco = NivelRisco.ALTO;
      tipo = 'configuracao_exposta';
      titulo = `Possíveis configurações ou chaves de API expostas em pastes`;
      descricao = `Foram encontradas ${pastesComConfigs.length} publicações que podem conter configurações, chaves de API ou outros dados sensíveis relacionados a "${termo}". `;
      descricao += `Chaves de API expostas podem permitir acesso não autorizado a serviços e recursos da empresa.`;
      recomendacao = 'Verifique os pastes identificados e revogue imediatamente quaisquer chaves de API ou credenciais expostas. Gere novas chaves e atualize os sistemas que as utilizam.';
    } else if (pastesComEmails.length > 0) {
      nivelRisco = NivelRisco.MEDIO;
      tipo = 'emails_expostos';
      titulo = `Menções em pastes podem conter listas de e-mails`;
      descricao = `Foram encontradas ${pastesComEmails.length} publicações que podem conter endereços de e-mail relacionados a "${termo}". `;
      descricao += `E-mails expostos podem ser usados em campanhas de phishing direcionado.`;
      recomendacao = 'Analise os pastes para identificar quais e-mails foram expostos. Alerte os usuários sobre possíveis tentativas de phishing e reforce o treinamento de segurança.';
    } else {
      titulo = `Termo "${termo}" encontrado em ${dados.length} paste(s) públicos`;
      descricao = `O termo "${termo}" aparece em ${dados.length} publicação(ões) indexadas pelo PSBDMP. `;
      descricao += `Isso pode indicar menções legítimas, discussões ou potencial exposição de informações. Uma análise manual é recomendada para determinar o contexto.`;
      recomendacao = 'Revise os pastes encontrados para determinar se contêm informações sensíveis da empresa. Se necessário, solicite remoção aos sites de hospedagem.';
    }
    
    achados.push({
      fonte: FonteInformacao.PSBDMP,
      nivelRisco,
      tipo,
      tipoEntidade: TipoEntidade.TEXTO,
      entidade: termo,
      titulo,
      descricao,
      recomendacao,
      evidencia: {
        termoBuscado: termo,
        totalPastes: dados.length,
        pastesComSenhas: pastesComSenhas.length,
        pastesComConfigs: pastesComConfigs.length,
        pastesComEmails: pastesComEmails.length,
        amostras: dados.slice(0, 10).map(p => ({
          id: p.id,
          tags: p.tags,
          tamanho: p.length,
          data: p.time,
          previewTexto: p.text?.slice(0, 200),
        })),
      },
    });
  }
  
  return {
    achados,
    itensEncontrados: dados.length,
    metadados: {
      termo,
      totalEncontrado: dados.length,
    },
  };
}
