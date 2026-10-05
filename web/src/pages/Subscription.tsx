import { CalendarClock, CreditCard, ExternalLink, Server, ShieldCheck } from 'lucide-react';
import { Breadcrumb, ErrorBox, PageLoader } from '../components/ui';
import { Card } from '../components/controls';
import { useApi } from '../hooks';

interface LicenseResp {
  license: { plan: string; plan_name: string; max_servers: number; period_end: string | null; status: string } | null;
  unlimited: boolean;
  platform: boolean;
  servers_used: number;
  tokens_pending: number;
  buy_url: string;
  renew_url: string;
  site_url: string;
}

/** The customer's plan: servers paid for and in use, until when, and where to buy more. */
export default function Subscription() {
  const { data, error } = useApi<LicenseResp>('/api/license', 60_000);
  if (error && !data) return <ErrorBox message={error} />;
  if (!data) return <PageLoader />;
  const lic = data.license;
  const end = lic?.period_end ? new Date(lic.period_end) : null;
  const daysLeft = end ? Math.ceil((end.getTime() - Date.now()) / 86400_000) : null;
  const expired = !!lic && (lic.status !== 'active' || (daysLeft !== null && daysLeft < 0));
  const max = lic?.max_servers ?? 0;
  const pct = max ? Math.min(100, Math.round((data.servers_used / max) * 100)) : 0;
  return (
    <div className="space-y-6">
      <div>
        <Breadcrumb items={['Overview', 'Subscription']} />
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-navy-900">
          <CreditCard className="h-6 w-6" /> Subscription
        </h1>
        <p className="text-sm text-slate-500">Your xPGuard plan: how many servers you can protect and until when.</p>
      </div>

      {data.unlimited ? (
        <Card title="No limits" desc="This account runs the portal: servers can be added without a plan.">{null}</Card>
      ) : (
        <>
          {expired && (
            <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-800">
              Your subscription is not active. Servers already connected stay protected, but no new server can be added until you renew.
            </div>
          )}
          {!expired && daysLeft !== null && daysLeft <= 7 && (
            <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
              Your plan ends in {daysLeft} day{daysLeft === 1 ? '' : 's'}. Renew it to keep adding servers and receiving updates without a break.
            </div>
          )}
          <div className="grid gap-4 md:grid-cols-3">
            <div className="card flex items-center gap-4 p-5">
              <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-blue-50 text-blue-600">
                <ShieldCheck />
              </span>
              <span>
                <span className="block text-xs text-slate-500">Plan</span>
                <span className="block text-lg font-semibold text-navy-900">{lic!.plan_name || lic!.plan}</span>
                <span className={`text-xs font-medium ${expired ? 'text-red-600' : 'text-emerald-700'}`}>{expired ? 'Not active' : 'Active'}</span>
              </span>
            </div>
            <div className="card p-5">
              <div className="flex items-center gap-4">
                <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-50 text-emerald-600">
                  <Server />
                </span>
                <span>
                  <span className="block text-xs text-slate-500">Servers</span>
                  <span className="block text-lg font-semibold text-navy-900">
                    {data.servers_used} of {max} in use
                  </span>
                  {data.tokens_pending > 0 && <span className="text-xs text-slate-500">{data.tokens_pending} install token(s) waiting</span>}
                </span>
              </div>
              <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-100">
                <div className={`h-full rounded-full ${pct >= 100 ? 'bg-red-500' : 'bg-emerald-500'}`} style={{ width: `${pct}%` }} />
              </div>
            </div>
            <div className="card flex items-center gap-4 p-5">
              <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-orange-50 text-orange-600">
                <CalendarClock />
              </span>
              <span>
                <span className="block text-xs text-slate-500">Paid until</span>
                <span className="block text-lg font-semibold text-navy-900">{end ? end.toLocaleDateString() : 'No end date'}</span>
                {daysLeft !== null && daysLeft >= 0 && <span className="text-xs text-slate-500">{daysLeft} days left</span>}
              </span>
            </div>
          </div>
          <Card title="Buy and renew" desc="Each server licence lets you connect one more server. Licences, renewals and invoices are on the xPGuard website, signed in with this email.">
            <div className="mt-3 flex flex-wrap gap-2">
              {data.buy_url && (
                <a className="btn-primary" href={data.buy_url} target="_blank" rel="noreferrer">
                  <Server className="h-4 w-4" /> Buy more servers
                </a>
              )}
              {data.renew_url && (
                <a className="btn-outline" href={data.renew_url} target="_blank" rel="noreferrer">
                  <ExternalLink className="h-4 w-4" /> Renew, invoices and billing
                </a>
              )}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
