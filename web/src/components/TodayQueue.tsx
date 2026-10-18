import { Link } from 'react-router-dom';
import { ArrowRight, CheckCircle2, ListTodo } from 'lucide-react';
import { useApi } from '../hooks';
import { useAuth } from '../auth';

interface Health {
  summary: { total: number; offline: number; outdated: number; problems: number };
}

/** "What needs me today": the queue before the numbers. */
export function TodayQueue() {
  const platform = useAuth().user?.platform !== false;
  const health = useApi<Health>('/api/fleet/health', 120_000);
  const req = useApi<{ open: number }>(platform ? '/api/unblock-requests' : null, 120_000);
  const h = health.data?.summary;
  const items: { n: number; text: string; to: string; tone: string }[] = [];
  if (h?.offline) items.push({ n: h.offline, text: `server${h.offline > 1 ? 's' : ''} offline`, to: '/fleet', tone: 'text-red-600' });
  if (h && h.problems - h.offline > 0) items.push({ n: h.problems - h.offline, text: 'server(s) with a problem to fix', to: '/fleet', tone: 'text-amber-600' });
  if (h?.outdated) items.push({ n: h.outdated, text: 'agent(s) to update', to: '/fleet', tone: 'text-amber-600' });
  if (req.data?.open) items.push({ n: req.data.open, text: `unblock request${req.data.open > 1 ? 's' : ''} waiting`, to: '/blocks?tab=requests', tone: 'text-red-600' });
  if (!h) return null;
  return (
    <section className="card p-5">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="flex items-center gap-2 font-semibold text-navy-900">
          <ListTodo className="h-5 w-5" /> Today
        </h2>
        {platform && (
          <Link to="/learning" className="text-sm text-navy-700 hover:underline">
            Rule approvals & learning <ArrowRight className="inline h-3.5 w-3.5" />
          </Link>
        )}
      </div>
      {items.length === 0 ? (
        <p className="flex items-center gap-2 text-sm text-slate-500">
          <CheckCircle2 className="h-4 w-4 text-emerald-600" /> Nothing waiting: every server is online and healthy.
        </p>
      ) : (
        <ul className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {items.map((i) => (
            <li key={i.text}>
              <Link to={i.to} className="flex items-center gap-3 rounded-lg border border-slate-200 px-3 py-2 hover:bg-slate-50">
                <span className={`text-2xl font-bold ${i.tone}`}>{i.n}</span>
                <span className="text-sm text-slate-600">{i.text}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
