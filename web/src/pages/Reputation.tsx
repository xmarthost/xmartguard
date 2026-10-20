import { lazy, Suspense } from 'react';
import { useSearchParams } from 'react-router-dom';
import { SectionLoader } from '../components/ui';
import { Tabs } from '../components/controls';

const IPReputation = lazy(() => import('./Firewall').then((m) => ({ default: m.IPReputation })));
const ServerDomainReputation = lazy(() => import('./Mail').then((m) => ({ default: m.ServerDomainReputation })));

type Tab = 'ip' | 'domains';

/** Reputation: is this server, or one of its websites, on a blocklist? */
export default function Reputation({ initial }: { initial?: Tab }) {
  const [sp, setSp] = useSearchParams();
  const tab: Tab = sp.get('tab') === 'domains' || sp.get('tab') === 'ip' ? (sp.get('tab') as Tab) : (initial ?? 'ip');
  return (
    <div className="space-y-4">
      <Tabs
        tabs={[
          { v: 'ip', l: 'Server IPs' },
          { v: 'domains', l: 'Websites' },
        ]}
        value={tab}
        onChange={(v) => setSp({ tab: v }, { replace: true })}
      />
      <Suspense fallback={<SectionLoader />}>{tab === 'ip' ? <IPReputation /> : <ServerDomainReputation />}</Suspense>
    </div>
  );
}
