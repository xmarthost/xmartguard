import SetPassword from './pages/SetPassword';
import Subscription from './pages/Subscription';
import { lazy, Suspense, type ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AuthProvider, can, useAuth } from './auth';
import Layout from './components/Layout';
import { ComingSoon, PageLoader } from './components/ui';
import Login from './pages/Login';

// Pages load on first use (smaller first download).
const AIScanner = lazy(() => import('./pages/AIScanner'));
const Overview = lazy(() => import('./pages/Overview'));
const ServerList = lazy(() => import('./pages/ServerList'));
const AddServer = lazy(() => import('./pages/AddServer'));
const ServerDashboard = lazy(() => import('./pages/ServerDashboard'));
const Monitoring = lazy(() => import('./pages/Monitoring'));
const AccountPage = lazy(() => import('./pages/Admin').then((m) => ({ default: m.AccountPage })));
const SecurityLogPage = lazy(() => import('./pages/Admin').then((m) => ({ default: m.SecurityLogPage })));
const SupportPage = lazy(() => import('./pages/Admin').then((m) => ({ default: m.SupportPage })));
const UsersPage = lazy(() => import('./pages/Admin').then((m) => ({ default: m.UsersPage })));
const ManualScans = lazy(() => import('./pages/Scanner').then((m) => ({ default: m.ManualScans })));
const ScannerLogs = lazy(() => import('./pages/Scanner').then((m) => ({ default: m.ScannerLogs })));
const FirewallPage = lazy(() => import('./pages/Firewall').then((m) => ({ default: m.FirewallPage })));
const TrustedServices = lazy(() => import('./pages/TrustedServices'));
const MailProtection = lazy(() => import('./pages/MailProtection'));
const FleetDomainReputation = lazy(() => import('./pages/DomainReputation'));
const CaptchaPage = lazy(() => import('./pages/CaptchaPage'));
const SecurityMonitor = lazy(() => import('./pages/SecurityMonitor'));
const ServerAudit = lazy(() => import('./pages/ServerAudit'));
const LearningCenter = lazy(() => import('./pages/LearningCenter'));
const BlockLookup = lazy(() => import('./pages/BlockLookup'));
const FleetHealth = lazy(() => import('./pages/FleetHealth'));
const SecurityEvents = lazy(() => import('./pages/SecurityEvents'));
const Reputation = lazy(() => import('./pages/Reputation'));
const AllowList = lazy(() => import('./pages/AllowList'));
const Unblock = lazy(() => import('./pages/Unblock'));
const SettingsPage = lazy(() => import('./pages/Settings'));
const CMSThreats = lazy(() => import('./pages/CMS').then((m) => ({ default: m.CMSThreats })));
const DBScanner = lazy(() => import('./pages/CMS').then((m) => ({ default: m.DBScanner })));
const OutgoingSpam = lazy(() => import('./pages/Mail').then((m) => ({ default: m.OutgoingSpam })));
const MassOperations = lazy(() => import('./pages/MassOperations'));
const CustomerServers = lazy(() => import('./pages/CustomerServers'));
const KnowledgeBase = lazy(() => import('./pages/KnowledgeBase'));
const AIConnector = lazy(() => import('./pages/AIConnector'));
const WafRuleSets = lazy(() => import('./pages/WafRuleSets'));
const AppearancePage = lazy(() => import('./pages/AppearancePage'));
const IPDBPage = lazy(() => import('./pages/IPDB'));

function Protected({ children, role }: { children: ReactNode; role?: 'owner' | 'admin' }) {
  const { user, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <PageLoader />;
  if (!user) return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
  if (role && !can(user, role)) return <Layout><ComingSoon title="Not allowed" milestone="your administrator's permission" /></Layout>;
  // Pages load on first use; the menu stays while one loads.
  return (
    <Layout>
      <Suspense fallback={<PageLoader />}>{children}</Suspense>
    </Layout>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/unblock" element={<Suspense fallback={<PageLoader />}><Unblock /></Suspense>} />
        <Route path="/blocks" element={<Protected><BlockLookup /></Protected>} />
        <Route path="/fleet" element={<Protected><FleetHealth /></Protected>} />
        <Route path="/set-password" element={<SetPassword />} />
        <Route path="/subscription" element={<Protected><Subscription /></Protected>} />
        <Route path="/" element={<Protected><Overview /></Protected>} />
        <Route path="/servers" element={<Protected><ServerList /></Protected>} />
        <Route path="/servers/add" element={<Protected role="admin"><AddServer /></Protected>} />
        <Route path="/servers/:id" element={<Protected><ServerDashboard /></Protected>} />
        <Route path="/servers/:id/monitoring" element={<Protected><Monitoring /></Protected>} />
        <Route path="/servers/:id/scanner" element={<Protected><ManualScans /></Protected>} />
        <Route path="/servers/:id/scanner-logs" element={<Protected><ScannerLogs /></Protected>} />
        <Route path="/servers/:id/firewall" element={<Protected><FirewallPage /></Protected>} />
        <Route path="/servers/:id/firewall-logs" element={<Protected><SecurityEvents initial="firewall" /></Protected>} />
        <Route path="/servers/:id/ip-reputation" element={<Protected><Reputation initial="ip" /></Protected>} />
        <Route path="/servers/:id/reputation" element={<Protected><Reputation /></Protected>} />
        <Route path="/servers/:id/osm" element={<Protected><OutgoingSpam /></Protected>} />
        <Route path="/servers/:id/domain-reputation" element={<Protected><Reputation initial="domains" /></Protected>} />
        <Route path="/servers/:id/cms" element={<Protected><CMSThreats /></Protected>} />
        <Route path="/servers/:id/db-scanner" element={<Protected><DBScanner /></Protected>} />
        <Route path="/servers/:id/waf-logs" element={<Protected><SecurityEvents initial="waf" /></Protected>} />
        <Route path="/servers/:id/events" element={<Protected><SecurityEvents /></Protected>} />
        <Route path="/servers/:id/allow" element={<Protected><AllowList /></Protected>} />
        <Route path="/servers/:id/bot-attacks" element={<Protected><SecurityEvents initial="bots" /></Protected>} />
        <Route path="/servers/:id/ipdb" element={<Protected><SecurityEvents initial="ipdb" /></Protected>} />
        <Route path="/servers/:id/settings" element={<Protected><SettingsPage /></Protected>} />
        <Route path="/servers/:id/security-monitor" element={<Protected><SecurityMonitor /></Protected>} />
        <Route path="/servers/:id/server-audit" element={<Protected><ServerAudit /></Protected>} />
        <Route path="/servers/:id/:module" element={<Protected><ComingSoon title="Coming soon" milestone="an upcoming release" /></Protected>} />
        <Route path="/ipdb" element={<Protected><IPDBPage /></Protected>} />
        <Route path="/ai" element={<Protected><AIScanner /></Protected>} />
        <Route path="/waf-rulesets" element={<Protected><WafRuleSets /></Protected>} />
        <Route path="/trusted-services" element={<Protected><TrustedServices /></Protected>} />
        <Route path="/mail-protection" element={<Protected><MailProtection /></Protected>} />
        <Route path="/domain-reputation" element={<Protected><FleetDomainReputation /></Protected>} />
        <Route path="/captcha-page" element={<Protected><CaptchaPage /></Protected>} />
        <Route path="/waf-intel" element={<Navigate to="/learning?tab=names" replace />} />
        <Route path="/appearance" element={<Protected><AppearancePage /></Protected>} />
        <Route path="/ai-connector" element={<Protected role="admin"><AIConnector /></Protected>} />
        <Route path="/mass-operations" element={<Protected><MassOperations /></Protected>} />
        <Route path="/all-servers" element={<Protected><CustomerServers /></Protected>} />
        <Route path="/ai-learning" element={<Navigate to="/learning?tab=ai" replace />} />
        <Route path="/learning" element={<Protected><LearningCenter /></Protected>} />
        <Route path="/xpguard-learning" element={<Navigate to="/learning?tab=exports" replace />} />
        <Route path="/users" element={<Protected role="owner"><UsersPage /></Protected>} />
        <Route path="/account" element={<Protected><AccountPage /></Protected>} />
        <Route path="/security" element={<Protected role="admin"><SecurityLogPage /></Protected>} />
        <Route path="/kb" element={<Protected><KnowledgeBase /></Protected>} />
        <Route path="/support" element={<Protected><SupportPage /></Protected>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
