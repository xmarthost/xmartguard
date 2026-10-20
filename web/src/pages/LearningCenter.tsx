import { lazy, Suspense } from 'react';
import { useSearchParams } from 'react-router-dom';
import { GraduationCap } from 'lucide-react';
import { Breadcrumb, SectionLoader } from '../components/ui';
import { Tabs } from '../components/controls';
import { can, useAuth } from '../auth';

const RuleApprovals = lazy(() => import('./RuleApprovals'));
const WafIntel = lazy(() => import('./WafIntel'));
const AILearning = lazy(() => import('./AILearning'));
const LearningExport = lazy(() => import('./LearningExport'));

type Tab = 'approvals' | 'names' | 'ai' | 'exports';

/** Master: everything the portal learns, in one place. Nothing is learned
 *  on its own: each tab is a report with the administrator's decisions. */
export default function LearningCenter() {
  const [params, setParams] = useSearchParams();
  const admin = can(useAuth().user, 'admin');
  const tabs: { v: Tab; l: string }[] = [
    { v: 'approvals', l: 'Rule approvals' },
    { v: 'names', l: 'Web shell names & patches' },
    { v: 'ai', l: 'AI report' },
    ...(admin ? [{ v: 'exports' as Tab, l: 'Exports' }] : []),
  ];
  const tab = (tabs.find((t) => t.v === params.get('tab'))?.v ?? 'approvals') as Tab;
  return (
    <div className="space-y-5">
      <Breadcrumb items={['Learning Center']} />
      <div className="max-w-3xl">
        <h1 className="h-title flex items-center gap-2">
          <GraduationCap className="h-6 w-6" /> Learning Center
        </h1>
        <p className="text-sm text-slate-500">
          Nothing is learned automatically. New rules watch before they block, names and AI findings wait for your decision, and exports go to review.
        </p>
      </div>
      <div className="overflow-x-auto">
        <Tabs tabs={tabs} value={tab} onChange={(v) => setParams({ tab: v }, { replace: true })} />
      </div>
      <Suspense fallback={<SectionLoader />}>
        {tab === 'approvals' && <RuleApprovals />}
        {tab === 'names' && <WafIntel />}
        {tab === 'ai' && <AILearning />}
        {tab === 'exports' && <LearningExport />}
      </Suspense>
    </div>
  );
}
