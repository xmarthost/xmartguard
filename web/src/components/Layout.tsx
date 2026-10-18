import type { ReactNode } from 'react';
import { useMatch } from 'react-router-dom';
import {
  BookOpen, BadgeCheck, ShieldOff, Award, ShieldQuestion, GraduationCap, Activity, BrainCircuit, Cable, Palette, ShieldHalf, Cpu, HeartPulse, ScanSearch as ScanSearchIcon, MailWarning, DatabaseZap, LayoutTemplate, Globe2, ShieldAlert, Bug, FileWarning, ListX, Radar, Flame, LayoutDashboard, Layers, LifeBuoy, CreditCard, Mail, Server as ServerIcon, Settings, ShieldCheck, ShieldBan, Users, ClipboardCheck,
} from 'lucide-react';
import { useAuth } from '../auth';
import { useApi } from '../hooks';
import type { Server } from '../api';
import ModernLayout from './ModernLayout';

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  end?: boolean;
}

interface RailEntry {
  label: string;
  icon: ReactNode;
  to?: string;
  end?: boolean;
  children?: NavItem[];
}

export default function Layout({ children }: { children: ReactNode }) {
  const serverMatch = useMatch('/servers/:id/*');
  const serverId = serverMatch?.params.id && serverMatch.params.id !== 'add' ? serverMatch.params.id : null;
  const { data } = useApi<{ server: Server }>(serverId ? `/api/servers/${serverId}` : null);
  const platform = useAuth().user?.platform !== false;

  const base = `/servers/${serverId}`;
  const entries: RailEntry[] = serverId
    ? [
        { label: 'Server List', icon: <ServerIcon />, to: '/servers', end: true },
        { label: 'Dashboard', icon: <LayoutDashboard />, to: base, end: true },
        { label: 'Website Scores', icon: <Award />, to: `${base}/scores` },
        {
          label: 'Virus Scanner',
          icon: <Bug />,
          children: [
            { to: `${base}/scanner`, label: 'Manual Scans', icon: <ScanSearchIcon /> },
            { to: `${base}/scanner-logs`, label: 'Scanner Logs', icon: <FileWarning /> },
            { to: `${base}/cms`, label: 'CMS Threats', icon: <LayoutTemplate /> },
            { to: `${base}/db-scanner`, label: 'DB Scanner', icon: <DatabaseZap /> },
          ],
        },
        {
          label: 'Protection',
          icon: <ShieldAlert />,
          children: [
            { to: `${base}/firewall`, label: 'Firewall', icon: <Flame /> },
            { to: `${base}/events`, label: 'Security Events', icon: <ListX /> },
            { to: `${base}/allow`, label: 'Allow list', icon: <BadgeCheck /> },
            { to: `${base}/osm`, label: 'Outgoing Spam Monitor', icon: <MailWarning /> },
          ],
        },
        {
          label: 'Server Health',
          icon: <HeartPulse />,
          children: [
            { to: `${base}/monitoring`, label: 'System Monitoring', icon: <Activity /> },
            { to: `${base}/reputation`, label: 'Reputation', icon: <Radar /> },
            { to: `${base}/security-monitor`, label: 'Process & Cron Monitor', icon: <Cpu /> },
            { to: `${base}/server-audit`, label: 'Server Audit', icon: <ClipboardCheck /> },
          ],
        },
        { label: 'Settings', icon: <Settings />, to: `${base}/settings` },
      ]
    : platform
    ? [
        { label: 'Overview', icon: <LayoutDashboard />, to: '/', end: true },
        { label: 'Server List', icon: <ServerIcon />, to: '/servers', end: true },
        { label: 'All Servers', icon: <Users />, to: '/all-servers' },
        { label: 'Fleet Health', icon: <Activity />, to: '/fleet' },
        { label: 'Why blocked?', icon: <ShieldOff />, to: '/blocks' },
        {
          label: 'Web Protection',
          icon: <ShieldHalf />,
          children: [
            { to: '/waf-rulesets', label: 'WAF Rule Sets', icon: <ShieldHalf /> },
            { to: '/captcha-page', label: 'CAPTCHA Page', icon: <ShieldQuestion /> },
            { to: '/ipdb', label: 'IPDB', icon: <ShieldBan /> },
            { to: '/trusted-services', label: 'Trusted Services', icon: <BadgeCheck /> },
            { to: '/mail-protection', label: 'Mail Protection', icon: <Mail /> },
            { to: '/domain-reputation', label: 'Domain Reputation', icon: <Globe2 /> },
          ],
        },
        {
          label: 'AI',
          icon: <BrainCircuit />,
          children: [
            { to: '/ai', label: 'AI Scanner', icon: <BrainCircuit /> },
            { to: '/ai-connector', label: 'AI Connector', icon: <Cable /> },
          ],
        },
        { label: 'Learning Center', icon: <GraduationCap />, to: '/learning' },
        { label: 'Mass Operations', icon: <Layers />, to: '/mass-operations' },
        { label: 'Appearance', icon: <Palette />, to: '/appearance' },
      ]
    : [
        // Customers: their servers and account; master settings are the provider's.
        { label: 'Overview', icon: <LayoutDashboard />, to: '/', end: true },
        { label: 'Server List', icon: <ServerIcon />, to: '/servers', end: true },
        { label: 'Fleet Health', icon: <Activity />, to: '/fleet' },
        { label: 'Why blocked?', icon: <ShieldOff />, to: '/blocks' },
        { label: 'Mass Operations', icon: <Layers />, to: '/mass-operations' },
        { label: 'AI Connector', icon: <Cable />, to: '/ai-connector' },
        { label: 'Subscription', icon: <CreditCard />, to: '/subscription' },
      ];
  const bottom: RailEntry[] = [
    { label: 'Security Log', icon: <ShieldCheck />, to: '/security' },
    { label: 'Knowledge Base', icon: <BookOpen />, to: '/kb' },
    { label: 'Support', icon: <LifeBuoy />, to: '/support' },
  ];
  return (
    <ModernLayout entries={entries} bottom={bottom}>
      {children}
    </ModernLayout>
  );
}
