// ============================================================================
// SENTINELA - Layout Principal
// Design inspirado no Justinianus.AI
// ============================================================================

import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useState } from 'react';
import {
  LayoutDashboard,
  Building2,
  Radar,
  Settings,
  Users,
  LogOut,
  Menu,
  X,
  Shield,
  Bell,
  ChevronDown,
} from 'lucide-react';
import { api } from '../../services/api';

const navegacao = [
  { href: '/dashboard', label: 'Painel Geral', icone: LayoutDashboard },
  { href: '/empresas', label: 'Empresas Monitoradas', icone: Building2 },
  { href: '/varreduras', label: 'Varreduras', icone: Radar },
  { href: '/configuracoes', label: 'Configurações', icone: Settings },
  { href: '/usuarios', label: 'Usuários', icone: Users },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [menuMobileAberto, setMenuMobileAberto] = useState(false);
  const [menuUsuarioAberto, setMenuUsuarioAberto] = useState(false);
  
  const usuario = api.getUsuarioLogado();
  
  const handleLogout = () => {
    api.logout();
    navigate('/login');
  };
  
  const isAtivo = (href: string) => {
    if (href === '/dashboard') {
      return location.pathname === '/dashboard' || location.pathname === '/';
    }
    return location.pathname.startsWith(href);
  };
  
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-[1800px] mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <Link to="/dashboard" className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-primary-600 flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div className="hidden sm:block">
                <span className="text-xl font-bold text-gray-900">Sentinela</span>
                <span className="text-[10px] text-gray-500 block -mt-1">Inteligência de Ameaças</span>
              </div>
            </Link>
            
            {/* Navegação Desktop */}
            <nav className="hidden lg:flex items-center gap-1">
              {navegacao.map((item) => (
                <Link
                  key={item.href}
                  to={item.href}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-[13px] font-medium transition-all ${
                    isAtivo(item.href)
                      ? 'bg-primary-50 text-primary-700 border border-primary-200'
                      : 'text-gray-600 hover:bg-gray-100'
                  }`}
                >
                  <item.icone className="w-4 h-4" />
                  <span>{item.label}</span>
                </Link>
              ))}
            </nav>
            
            {/* Ações */}
            <div className="flex items-center gap-3">
              {/* Notificações */}
              <button className="relative p-2 rounded-lg text-gray-500 hover:bg-gray-100 transition-colors">
                <Bell className="w-5 h-5" />
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
              </button>
              
              {/* Menu do Usuário */}
              <div className="relative">
                <button
                  onClick={() => setMenuUsuarioAberto(!menuUsuarioAberto)}
                  className="flex items-center gap-2 p-2 rounded-lg hover:bg-gray-100 transition-colors"
                >
                  <div className="w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center">
                    <span className="text-sm font-semibold text-primary-700">
                      {usuario?.nome?.charAt(0) || 'U'}
                    </span>
                  </div>
                  <div className="hidden md:block text-left">
                    <div className="text-sm font-medium text-gray-900">{usuario?.nome || 'Usuário'}</div>
                    <div className="text-xs text-gray-500">{usuario?.perfil || 'Perfil'}</div>
                  </div>
                  <ChevronDown className="w-4 h-4 text-gray-400" />
                </button>
                
                {menuUsuarioAberto && (
                  <div className="absolute right-0 mt-2 w-56 bg-white rounded-xl shadow-lg border border-gray-200 py-2 animate-fade-in">
                    <div className="px-4 py-2 border-b border-gray-100">
                      <div className="text-sm font-medium text-gray-900">{usuario?.nome}</div>
                      <div className="text-xs text-gray-500">{usuario?.email}</div>
                    </div>
                    <div className="px-2 py-2">
                      <button
                        onClick={handleLogout}
                        className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                      >
                        <LogOut className="w-4 h-4" />
                        Sair da conta
                      </button>
                    </div>
                  </div>
                )}
              </div>
              
              {/* Menu Mobile */}
              <button
                onClick={() => setMenuMobileAberto(!menuMobileAberto)}
                className="lg:hidden p-2 rounded-lg text-gray-500 hover:bg-gray-100 transition-colors"
              >
                {menuMobileAberto ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
              </button>
            </div>
          </div>
        </div>
        
        {/* Menu Mobile */}
        {menuMobileAberto && (
          <div className="lg:hidden border-t border-gray-200 bg-white">
            <nav className="p-4 space-y-1">
              {navegacao.map((item) => (
                <Link
                  key={item.href}
                  to={item.href}
                  onClick={() => setMenuMobileAberto(false)}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium ${
                    isAtivo(item.href)
                      ? 'bg-primary-50 text-primary-700 border border-primary-200'
                      : 'text-gray-600 hover:bg-gray-100'
                  }`}
                >
                  <item.icone className="w-5 h-5" />
                  <span>{item.label}</span>
                </Link>
              ))}
            </nav>
          </div>
        )}
      </header>
      
      {/* Conteúdo */}
      <main className="max-w-[1800px] mx-auto px-4 sm:px-6 py-6 sm:py-8">
        {children}
      </main>
      
      {/* Overlay para fechar menus */}
      {(menuUsuarioAberto || menuMobileAberto) && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => {
            setMenuUsuarioAberto(false);
            setMenuMobileAberto(false);
          }}
        />
      )}
    </div>
  );
}
