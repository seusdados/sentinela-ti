// ============================================================================
// SENTINELA - Página de Usuários
// Gerenciamento de usuários da organização
// ============================================================================

import { useState, useEffect } from 'react';
import {
  Users,
  Plus,
  Shield,
  ShieldCheck,
  Eye,
  UserCircle,
  Mail,
  Calendar,
  AlertCircle,
} from 'lucide-react';
import { api } from '../services/api';

const PERFIS = {
  ADMINISTRADOR: { label: 'Administrador', descricao: 'Acesso total ao sistema', cor: 'badge-critico' },
  ANALISTA: { label: 'Analista', descricao: 'Pode criar varreduras e visualizar achados', cor: 'badge-medio' },
  VISUALIZADOR: { label: 'Visualizador', descricao: 'Apenas visualização de dados', cor: 'badge-info' },
};

function formatarData(data: string) {
  if (!data) return 'Nunca';
  return new Date(data).toLocaleDateString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export default function UsuariosPage() {
  const [usuarios, setUsuarios] = useState<any[]>([]);
  const [carregando, setCarregando] = useState(true);
  const [modalAberto, setModalAberto] = useState(false);
  const [formDados, setFormDados] = useState({
    nome: '',
    email: '',
    senha: '',
    perfil: 'VISUALIZADOR',
  });
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState('');
  
  useEffect(() => {
    carregarUsuarios();
  }, []);
  
  const carregarUsuarios = async () => {
    try {
      const resposta = await api.getUsuarios();
      setUsuarios(resposta.usuarios || []);
    } catch (erro) {
      console.error('Erro ao carregar usuários:', erro);
    } finally {
      setCarregando(false);
    }
  };
  
  const criarUsuario = async (e: React.FormEvent) => {
    e.preventDefault();
    setSalvando(true);
    setErro('');
    
    try {
      await api.criarUsuario(formDados);
      setModalAberto(false);
      setFormDados({ nome: '', email: '', senha: '', perfil: 'VISUALIZADOR' });
      carregarUsuarios();
    } catch (err: any) {
      setErro(err.message || 'Erro ao criar usuário');
    } finally {
      setSalvando(false);
    }
  };
  
  return (
    <div className="space-y-6">
      {/* Cabeçalho */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Usuários</h1>
          <p className="text-gray-500 mt-1">Gerencie os usuários que têm acesso à plataforma</p>
        </div>
        <button onClick={() => setModalAberto(true)} className="btn btn-primary">
          <Plus className="w-4 h-4" />
          Novo Usuário
        </button>
      </div>
      
      {/* Descrição dos Perfis */}
      <div className="card">
        <h3 className="font-semibold text-gray-900 mb-3">Perfis de Acesso</h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {Object.entries(PERFIS).map(([key, value]) => (
            <div key={key} className="p-3 bg-gray-50 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <ShieldCheck className="w-4 h-4 text-gray-400" />
                <span className={`badge ${value.cor}`}>{value.label}</span>
              </div>
              <p className="text-xs text-gray-500">{value.descricao}</p>
            </div>
          ))}
        </div>
      </div>
      
      {/* Lista de Usuários */}
      <div className="card overflow-hidden">
        {carregando ? (
          <div className="p-8 text-center">
            <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
            <p className="text-gray-500 mt-2">Carregando usuários...</p>
          </div>
        ) : usuarios.length === 0 ? (
          <div className="p-8 text-center">
            <Users className="w-12 h-12 mx-auto text-gray-300 mb-4" />
            <p className="text-gray-500">Nenhum usuário cadastrado</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Usuário</th>
                  <th>Perfil</th>
                  <th>Status</th>
                  <th>Último Acesso</th>
                  <th>Criado em</th>
                </tr>
              </thead>
              <tbody>
                {usuarios.map((usuario) => {
                  const perfilInfo = PERFIS[usuario.perfil as keyof typeof PERFIS] || { label: usuario.perfil, cor: 'badge-info' };
                  
                  return (
                    <tr key={usuario.id}>
                      <td>
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-full bg-primary-100 flex items-center justify-center">
                            <span className="text-sm font-semibold text-primary-700">
                              {usuario.nome?.charAt(0) || 'U'}
                            </span>
                          </div>
                          <div>
                            <p className="font-medium text-gray-900">{usuario.nome}</p>
                            <p className="text-sm text-gray-500 flex items-center gap-1">
                              <Mail className="w-3 h-3" />
                              {usuario.email}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className={`badge ${perfilInfo.cor}`}>{perfilInfo.label}</span>
                      </td>
                      <td>
                        {usuario.ativo ? (
                          <span className="badge badge-baixo">Ativo</span>
                        ) : (
                          <span className="badge bg-gray-100 text-gray-600">Inativo</span>
                        )}
                      </td>
                      <td className="text-gray-500 text-sm">
                        {formatarData(usuario.ultimoAcessoEm)}
                      </td>
                      <td className="text-gray-500 text-sm">
                        {formatarData(usuario.criadoEm)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      
      {/* Modal de Novo Usuário */}
      {modalAberto && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-xl max-w-md w-full p-6 animate-slide-up">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Cadastrar Novo Usuário</h2>
            
            {erro && (
              <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm flex items-center gap-2">
                <AlertCircle className="w-4 h-4" />
                {erro}
              </div>
            )}
            
            <form onSubmit={criarUsuario} className="space-y-4">
              <div>
                <label className="label">Nome completo</label>
                <input
                  type="text"
                  value={formDados.nome}
                  onChange={(e) => setFormDados({ ...formDados, nome: e.target.value })}
                  className="input"
                  placeholder="Ex: João da Silva"
                  required
                />
              </div>
              
              <div>
                <label className="label">Endereço de e-mail</label>
                <input
                  type="email"
                  value={formDados.email}
                  onChange={(e) => setFormDados({ ...formDados, email: e.target.value })}
                  className="input"
                  placeholder="joao@empresa.com.br"
                  required
                />
              </div>
              
              <div>
                <label className="label">Senha inicial</label>
                <input
                  type="password"
                  value={formDados.senha}
                  onChange={(e) => setFormDados({ ...formDados, senha: e.target.value })}
                  className="input"
                  placeholder="Mínimo 8 caracteres"
                  minLength={8}
                  required
                />
                <p className="text-xs text-gray-400 mt-1">
                  O usuário poderá alterar a senha após o primeiro acesso
                </p>
              </div>
              
              <div>
                <label className="label">Perfil de acesso</label>
                <select
                  value={formDados.perfil}
                  onChange={(e) => setFormDados({ ...formDados, perfil: e.target.value })}
                  className="input"
                  required
                >
                  {Object.entries(PERFIS).map(([key, value]) => (
                    <option key={key} value={key}>{value.label} - {value.descricao}</option>
                  ))}
                </select>
              </div>
              
              <div className="flex gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => {
                    setModalAberto(false);
                    setErro('');
                  }}
                  className="btn btn-secondary flex-1"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={salvando}
                  className="btn btn-primary flex-1"
                >
                  {salvando ? 'Salvando...' : 'Cadastrar Usuário'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
