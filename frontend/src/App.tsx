// ============================================================================
// SENTINELA - Aplicação Principal
// ============================================================================

import { Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { api } from './services/api';

// Layout
import Layout from './components/layout/Layout';

// Páginas
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import EmpresasPage from './pages/EmpresasPage';
import EmpresaDetalhePage from './pages/EmpresaDetalhePage';
import VarredurasPage from './pages/VarredurasPage';
import VarreduraDetalhePage from './pages/VarreduraDetalhePage';
import ConfiguracoesPage from './pages/ConfiguracoesPage';
import UsuariosPage from './pages/UsuariosPage';
import InteligenciaPage from './pages/InteligenciaPage';

// Componente de rota protegida
function RotaProtegida({ children }: { children: React.ReactNode }) {
  const token = api.getToken();
  
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  
  return <>{children}</>;
}

export default function App() {
  const [carregando, setCarregando] = useState(true);
  
  useEffect(() => {
    // Verificar se há token válido
    const token = api.getToken();
    setCarregando(false);
    
    if (!token && window.location.pathname !== '/login') {
      window.location.href = '/login';
    }
  }, []);
  
  if (carregando) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
      </div>
    );
  }
  
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      
      <Route
        path="/*"
        element={
          <RotaProtegida>
            <Layout>
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/empresas" element={<EmpresasPage />} />
                <Route path="/empresas/:id" element={<EmpresaDetalhePage />} />
                <Route path="/varreduras" element={<VarredurasPage />} />
                <Route path="/varreduras/:id" element={<VarreduraDetalhePage />} />
                <Route path="/configuracoes" element={<ConfiguracoesPage />} />
                <Route path="/usuarios" element={<UsuariosPage />} />
                <Route path="/inteligencia" element={<InteligenciaPage />} />
              </Routes>
            </Layout>
          </RotaProtegida>
        }
      />
    </Routes>
  );
}
