import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';
import { AuthProvider, can, useAuth } from './auth';
import Layout from './components/Layout';
import { ComingSoon, PageLoader } from './components/ui';
import Login from './pages/Login';
import Overview from './pages/Overview';
import ServerList from './pages/ServerList';
import AddServer from './pages/AddServer';
import ServerDashboard from './pages/ServerDashboard';
import Monitoring from './pages/Monitoring';
import { AccountPage, SecurityLogPage, SupportPage, UsersPage } from './pages/Admin';

function Protected({ children, role }: { children: ReactNode; role?: 'owner' | 'admin' }) {
  const { user, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <PageLoader />;
  if (!user) return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
  if (role && !can(user, role)) return <Layout><ComingSoon title="Not allowed" milestone="your administrator's permission" /></Layout>;
  return <Layout>{children}</Layout>;
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Protected><Overview /></Protected>} />
        <Route path="/servers" element={<Protected><ServerList /></Protected>} />
        <Route path="/servers/add" element={<Protected role="admin"><AddServer /></Protected>} />
        <Route path="/servers/:id" element={<Protected><ServerDashboard /></Protected>} />
        <Route path="/servers/:id/monitoring" element={<Protected><Monitoring /></Protected>} />
        <Route path="/servers/:id/scanner" element={<Protected><ComingSoon title="Virus Scanner" milestone="milestone M3" /></Protected>} />
        <Route path="/servers/:id/firewall" element={<Protected><ComingSoon title="Firewall" milestone="milestone M4" /></Protected>} />
        <Route path="/servers/:id/settings" element={<Protected><ComingSoon title="Server Settings" milestone="milestone M3" /></Protected>} />
        <Route path="/mass-operations" element={<Protected><ComingSoon title="Mass Operations" milestone="milestone M10" /></Protected>} />
        <Route path="/users" element={<Protected role="owner"><UsersPage /></Protected>} />
        <Route path="/account" element={<Protected><AccountPage /></Protected>} />
        <Route path="/security" element={<Protected role="admin"><SecurityLogPage /></Protected>} />
        <Route path="/support" element={<Protected><SupportPage /></Protected>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
