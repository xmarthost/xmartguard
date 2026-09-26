import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { lazy, Suspense, type ReactNode } from 'react';
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
import { ManualScans, ScannerLogs } from './pages/Scanner';
import { FirewallLogs, FirewallPage, IPReputation } from './pages/Firewall';
import SettingsPage from './pages/Settings';
import { BotAttacks, WafLogs } from './pages/WAF';
import { CMSThreats, DBScanner } from './pages/CMS';
const IPDBPage = lazy(() => import('./pages/IPDB'));
const ServerIPDB = lazy(() => import('./pages/ServerIPDB'));

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
        <Route path="/servers/:id/scanner" element={<Protected><ManualScans /></Protected>} />
        <Route path="/servers/:id/scanner-logs" element={<Protected><ScannerLogs /></Protected>} />
        <Route path="/servers/:id/firewall" element={<Protected><FirewallPage /></Protected>} />
        <Route path="/servers/:id/firewall-logs" element={<Protected><FirewallLogs /></Protected>} />
        <Route path="/servers/:id/ip-reputation" element={<Protected><IPReputation /></Protected>} />
        <Route path="/servers/:id/cms" element={<Protected><CMSThreats /></Protected>} />
        <Route path="/servers/:id/db-scanner" element={<Protected><DBScanner /></Protected>} />
        <Route path="/servers/:id/waf-logs" element={<Protected><WafLogs /></Protected>} />
        <Route path="/servers/:id/bot-attacks" element={<Protected><BotAttacks /></Protected>} />
        <Route path="/servers/:id/ipdb" element={<Protected><Suspense fallback={<PageLoader />}><ServerIPDB /></Suspense></Protected>} />
        <Route path="/servers/:id/settings" element={<Protected><SettingsPage /></Protected>} />
        <Route path="/servers/:id/:module" element={<Protected><ComingSoon title="Coming soon" milestone="an upcoming release" /></Protected>} />
        <Route path="/ipdb" element={<Protected><Suspense fallback={<PageLoader />}><IPDBPage /></Suspense></Protected>} />
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
