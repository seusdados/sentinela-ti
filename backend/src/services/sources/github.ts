// ============================================================================
// SENTINELA - Fonte: GitHub Code Search (Busca de Secrets em Código Público)
// ============================================================================
// 
// O GitHub hospeda milhões de repositórios públicos. Desenvolvedores às vezes
// cometem erros e fazem commit de credenciais, chaves de API e outros dados
// sensíveis. Esses dados ficam acessíveis publicamente e indexados.
//
// UTILIDADE: Detectar vazamentos de credenciais em código:
// - Chaves de API hardcoded
// - Senhas em arquivos de configuração
// - Tokens de acesso
// - Strings de conexão de banco de dados
// - Certificados e chaves privadas
// ============================================================================

import { FonteInformacao, NivelRisco, TipoEntidade } from '@prisma/client';
import { http } from '../httpClient';
import { ResultadoFonte, AchadoCandidato } from '../../types';

interface ResultadoGitHub {
  total_count: number;
  incomplete_results: boolean;
  items: {
    name: string;
    path: string;
    sha: string;
    url: string;
    git_url: string;
    html_url: string;
    repository: {
      id: number;
      name: string;
      full_name: string;
      owner: {
        login: string;
        type: string;
      };
      private: boolean;
      html_url: string;
      description?: string;
    };
    score: number;
    text_matches?: {
      object_url: string;
      object_type: string;
      property: string;
      fragment: string;
      matches: {
        text: string;
        indices: number[];
      }[];
    }[];
  }[];
}

// Padrões de busca para diferentes tipos de secrets
const PADROES_BUSCA = [
  { padrao: 'password', tipo: 'senha', risco: NivelRisco.CRITICO },
  { padrao: 'api_key', tipo: 'chave_api', risco: NivelRisco.CRITICO },
  { padrao: 'apikey', tipo: 'chave_api', risco: NivelRisco.CRITICO },
  { padrao: 'secret', tipo: 'secret', risco: NivelRisco.CRITICO },
  { padrao: 'token', tipo: 'token', risco: NivelRisco.ALTO },
  { padrao: 'private_key', tipo: 'chave_privada', risco: NivelRisco.CRITICO },
  { padrao: 'aws_access', tipo: 'credencial_aws', risco: NivelRisco.CRITICO },
  { padrao: 'database_url', tipo: 'conexao_banco', risco: NivelRisco.CRITICO },
  { padrao: 'jdbc:', tipo: 'conexao_banco', risco: NivelRisco.ALTO },
  { padrao: 'mongodb://', tipo: 'conexao_banco', risco: NivelRisco.ALTO },
];

export async function buscarSecretsEmCodigo(dominio: string, chaveApi?: string | null): Promise<ResultadoFonte> {
  const achados: AchadoCandidato[] = [];
  let totalEncontrado = 0;
  
  // Nome base da empresa (ex: "empresa" de "empresa.com.br")
  const nomeBase = dominio.split('.')[0];
  
  // Realizar buscas para cada padrão
  for (const { padrao, tipo, risco } of PADROES_BUSCA.slice(0, 5)) { // Limitar para não exceder rate limit
    const consulta = `"${dominio}" ${padrao}`;
    const url = `https://api.github.com/search/code?q=${encodeURIComponent(consulta)}&per_page=10`;
    
    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github.text-match+json',
    };
    
    if (chaveApi) {
      headers['Authorization'] = `Bearer ${chaveApi}`;
    }
    
    const resposta = await http.get<ResultadoGitHub>(url, { headers });
    
    if (!resposta.sucesso) {
      // Se for rate limit, parar de buscar
      if (resposta.erro?.limiteTaxa) {
        break;
      }
      continue;
    }
    
    const dados = resposta.dados;
    if (!dados || dados.total_count === 0) {
      continue;
    }
    
    totalEncontrado += dados.total_count;
    
    // Processar resultados
    for (const item of dados.items.slice(0, 3)) { // Limitar a 3 por padrão
      const repo = item.repository;
      const matches = item.text_matches || [];
      
      // Extrair trechos relevantes
      const fragmentos = matches
        .map(m => m.fragment)
        .filter(f => f && f.length > 0)
        .slice(0, 3);
      
      // Verificar se parece ser um secret real (não documentação)
      const pareceDocumentacao = fragmentos.some(f => 
        f.includes('example') ||
        f.includes('exemplo') ||
        f.includes('your_') ||
        f.includes('YOUR_') ||
        f.includes('xxx') ||
        f.includes('placeholder')
      );
      
      if (pareceDocumentacao) {
        continue; // Pular documentação e exemplos
      }
      
      const arquivosSensiveis = ['.env', 'config', 'settings', 'credentials', 'secrets'];
      const isArquivoSensivel = arquivosSensiveis.some(a => 
        item.path.toLowerCase().includes(a)
      );
      
      const nivelRiscoFinal = isArquivoSensivel ? NivelRisco.CRITICO : risco;
      
      achados.push({
        fonte: FonteInformacao.GITHUB,
        nivelRisco: nivelRiscoFinal,
        tipo: `secret_${tipo}`,
        tipoEntidade: TipoEntidade.CODIGO,
        entidade: item.html_url,
        titulo: `Possível ${traduzirTipo(tipo)} exposto em repositório público`,
        descricao: gerarDescricao(tipo, repo.full_name, item.path, fragmentos),
        recomendacao: gerarRecomendacao(tipo, repo.full_name),
        evidencia: {
          repositorio: repo.full_name,
          proprietario: repo.owner.login,
          tipoProprietario: repo.owner.type,
          arquivo: item.path,
          urlArquivo: item.html_url,
          tipoSecret: tipo,
          fragmentos: fragmentos.map(f => ofuscarSecrets(f)),
          pontuacaoRelevancia: item.score,
        },
      });
    }
    
    // Pausa para não exceder rate limit
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  return {
    achados,
    itensEncontrados: totalEncontrado,
    metadados: {
      dominioBuscado: dominio,
      padroesPesquisados: PADROES_BUSCA.slice(0, 5).map(p => p.padrao),
    },
  };
}

function traduzirTipo(tipo: string): string {
  const traducoes: Record<string, string> = {
    'senha': 'senha',
    'chave_api': 'chave de API',
    'secret': 'secret/segredo',
    'token': 'token de acesso',
    'chave_privada': 'chave privada',
    'credencial_aws': 'credencial AWS',
    'conexao_banco': 'string de conexão de banco de dados',
  };
  return traducoes[tipo] || tipo;
}

function gerarDescricao(tipo: string, repo: string, arquivo: string, fragmentos: string[]): string {
  let desc = `Foi encontrado código no repositório público "${repo}" que pode conter ${traduzirTipo(tipo)} relacionado à sua empresa. `;
  desc += `O arquivo "${arquivo}" contém referências que indicam possível exposição de credenciais. `;
  
  if (tipo === 'senha' || tipo === 'chave_api') {
    desc += `Credenciais expostas em repositórios públicos são uma das principais causas de invasões e vazamentos de dados, pois atacantes monitoram ativamente o GitHub em busca dessas informações.`;
  } else if (tipo === 'conexao_banco') {
    desc += `Strings de conexão expostas podem permitir acesso direto ao banco de dados se o servidor estiver acessível pela internet.`;
  } else if (tipo === 'chave_privada') {
    desc += `Chaves privadas expostas comprometem completamente a segurança dos sistemas que as utilizam.`;
  }
  
  return desc;
}

function gerarRecomendacao(tipo: string, repo: string): string {
  let rec = '';
  
  if (tipo === 'senha' || tipo === 'chave_api' || tipo === 'secret' || tipo === 'token') {
    rec = 'URGENTE: (1) Revogue ou altere imediatamente a credencial exposta. ';
    rec += '(2) Verifique os logs de acesso para identificar uso não autorizado. ';
    rec += '(3) Remova a credencial do histórico do Git usando git filter-branch ou BFG Repo-Cleaner. ';
    rec += '(4) Considere usar ferramentas como GitHub Secret Scanning ou GitGuardian para prevenir futuros vazamentos.';
  } else if (tipo === 'conexao_banco') {
    rec = 'URGENTE: Altere a senha do banco de dados imediatamente. Verifique se o banco está acessível pela internet e restrinja o acesso. ';
    rec += 'Analise os logs do banco para identificar acessos não autorizados.';
  } else if (tipo === 'chave_privada') {
    rec = 'URGENTE: Revogue o certificado/chave comprometido e gere um novo par de chaves. ';
    rec += 'Atualize todos os sistemas que dependem desta chave. Investigue possível uso não autorizado.';
  } else if (tipo === 'credencial_aws') {
    rec = 'URGENTE: Desative a chave AWS comprometida no console IAM imediatamente. ';
    rec += 'Verifique o CloudTrail para identificar atividades não autorizadas. ';
    rec += 'Audite os recursos AWS para identificar alterações suspeitas.';
  }
  
  return rec;
}

function ofuscarSecrets(texto: string): string {
  // Ofuscar possíveis secrets mantendo contexto
  return texto
    .replace(/(['"=:])\s*[A-Za-z0-9+/=_-]{20,}/g, '$1***OFUSCADO***')
    .replace(/password['":\s]*[^'"\s,}]{5,}/gi, 'password=***OFUSCADO***')
    .replace(/[a-f0-9]{32,}/gi, '***HASH_OFUSCADO***');
}
