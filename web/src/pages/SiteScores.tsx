import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Award, Download, FileText } from 'lucide-react';
import { Breadcrumb, Empty, ErrorBox, SectionLoader } from '../components/ui';
import { Card, agentCall, useAction, useAgent } from '../components/controls';
import { useServerName } from './Scanner';

interface Site {
  domain: string;
  path: string;
  owner: string;
  type: string;
  score: number;
  grade: string;
  todo: string[] | null;
}

const GRADE: Record<string, string> = {
  A: 'bg-emerald-100 text-emerald-800',
  B: 'bg-lime-100 text-lime-800',
  C: 'bg-amber-100 text-amber-800',
  D: 'bg-orange-100 text-orange-800',
  F: 'bg-red-100 text-red-800',
};

export function GradeBadge({ grade, score }: { grade: string; score?: number }) {
  return (
    <span className={`inline-flex h-9 min-w-9 items-center justify-center rounded-lg px-2 text-lg font-bold ${GRADE[grade] ?? GRADE.F}`} title={score !== undefined ? `${score}/100` : undefined}>
      {grade}
    </span>
  );
}

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);

/** A printable (save as PDF) page of a monthly report. */
function reportHTML(text: string, brand: string, host: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(brand)} security report</title>
<style>body{font:15px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#0f172a;max-width:760px;margin:40px auto;padding:0 20px}
h1{font-size:22px;margin:0}.sub{color:#64748b;margin:4px 0 24px}pre{white-space:pre-wrap;font:14px/1.6 ui-monospace,Menlo,Consolas,monospace;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:18px}</style>
</head><body><h1>${esc(brand)}</h1><div class="sub">Security report · ${esc(host)}</div><pre>${esc(text)}</pre></body></html>`;
}

/** Website scores: each website's grade and the few things to do for an A,
 *  and the monthly report. */
export default function SiteScores() {
  const { id } = useParams();
  const host = useServerName(id);
  const res = useAgent<{ sites: Site[] | null }>(id, 'sites.scores', {});
  const [q, setQ] = useState('');
  const sites = (res.data?.sites ?? []).filter((s) => !q || s.domain.includes(q.toLowerCase()) || s.owner.includes(q.toLowerCase()));
  const counts = (res.data?.sites ?? []).reduce<Record<string, number>>((m, s) => ((m[s.grade] = (m[s.grade] ?? 0) + 1), m), {});
  return (
    <div className="space-y-5">
      <Breadcrumb items={[host, 'Website Scores']} />
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="max-w-3xl">
          <h1 className="h-title flex items-center gap-2">
            <Award className="h-6 w-6" /> Website security scores
          </h1>
          <p className="text-sm text-slate-500">
            A to F for each website, from its malware history, core files, database, outdated software and the server audit, with what to do for an A.
          </p>
        </div>
        <input className="input w-56" placeholder="Filter by website or account" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="grid grid-cols-5 gap-2 sm:max-w-xl">
        {['A', 'B', 'C', 'D', 'F'].map((g) => (
          <div key={g} className="card flex items-center gap-2 p-3">
            <GradeBadge grade={g} />
            <span className="text-xl font-semibold text-navy-900">{counts[g] ?? 0}</span>
          </div>
        ))}
      </div>
      <Card>
        {res.error && <ErrorBox message={res.error.includes('unsupported') ? 'Update the agent to see website scores.' : res.error} />}
        {res.loading && !res.data ? (
          <SectionLoader />
        ) : sites.length === 0 ? (
          <Empty text="No websites found yet (the WordPress and CMS check lists them)." />
        ) : (
          <div className="divide-y divide-slate-100">
            {sites.map((s) => (
              <div key={s.path} className="flex items-start gap-4 py-3">
                <GradeBadge grade={s.grade} score={s.score} />
                <div className="min-w-0 flex-1">
                  <div className="font-medium text-navy-900">
                    {s.domain || s.path} <span className="text-sm font-normal text-slate-400">· {s.owner} · {s.type} · {s.score}/100</span>
                  </div>
                  {s.todo?.length ? (
                    <ul className="mt-1 list-disc pl-5 text-sm text-slate-600">
                      {s.todo.map((t) => (
                        <li key={t}>{t}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-emerald-700">Nothing to do.</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
      {id && <MonthlyReport serverId={id} host={host} owners={[...new Set((res.data?.sites ?? []).map((s) => s.owner).filter(Boolean))].sort()} />}
    </div>
  );
}

function MonthlyReport({ serverId, host, owners }: { serverId: string; host: string; owners: string[] }) {
  const months = Array.from({ length: 6 }, (_, i) => {
    const d = new Date();
    d.setDate(1);
    d.setMonth(d.getMonth() - i);
    return d.toISOString().slice(0, 7);
  });
  const [month, setMonth] = useState(months[1]);
  const [user, setUser] = useState('');
  const [text, setText] = useState<{ text: string; brand: string } | null>(null);
  const { run, busy } = useAction();
  const load = () => run(() => agentCall<{ text: string; brand: string }>(serverId, 'report.monthly', { month, user }).then(setText));
  return (
    <Card
      title="Monthly report"
      desc="What the protection did in a month: for the whole server, or one hosting account (what its owner gets by email when Settings » Notifications » Monthly security report is on)."
    >
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <select className="input w-40" value={month} onChange={(e) => (setMonth(e.target.value), setText(null))}>
          {months.map((m) => (
            <option key={m} value={m}>
              {new Date(m + '-01T00:00:00').toLocaleDateString(undefined, { month: 'long', year: 'numeric' })}
            </option>
          ))}
        </select>
        <select className="input w-48" value={user} onChange={(e) => (setUser(e.target.value), setText(null))}>
          <option value="">Whole server</option>
          {owners.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
        <button className="btn-outline" disabled={busy} onClick={load}>
          <FileText className="h-4 w-4" /> Show
        </button>
        {text && (
          <button
            className="btn-primary"
            onClick={() => {
              const blob = new Blob([reportHTML(text.text, text.brand || 'xPGuard', user ? `${user} on ${host}` : host)], { type: 'text/html' });
              const a = document.createElement('a');
              a.href = URL.createObjectURL(blob);
              a.download = `security-report-${user || 'server'}-${month}.html`;
              a.click();
              URL.revokeObjectURL(a.href);
            }}
          >
            <Download className="h-4 w-4" /> Download (print to PDF)
          </button>
        )}
      </div>
      {text && <pre className="mt-4 max-h-[28rem] overflow-auto rounded-lg border border-slate-200 bg-slate-50 p-4 text-xs whitespace-pre-wrap">{text.text}</pre>}
    </Card>
  );
}
