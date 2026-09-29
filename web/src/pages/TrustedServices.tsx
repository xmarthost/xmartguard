import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, Save, ShieldCheck } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Breadcrumb, ErrorBox, PageLoader } from '../components/ui';
import { Card, ListEditor, SettingRow, Toggle, agentCall, fmtTime, isIPorCIDR, useAction } from '../components/controls';
import { useApi } from '../hooks';

interface Svc {
  id: string;
  name: string;
  group: string;
  enabled: boolean;
  addresses: number;
  source: string;
  updated?: number;
  error?: string;
}

interface Config {
  enabled: boolean;
  disabled: string[];
  custom: string[];
}

interface Resp {
  config: Config;
  version: number;
  updated_at: string | null;
  services: Svc[];
  source: { id: string; hostname: string } | null;
  servers: { id: string; hostname: string; online: boolean }[];
}

/** Groups in display order, with what they protect. */
const GROUPS: [string, string, string][] = [
  ['search', 'Search engines', 'Crawlers that index the sites (SEO): Google, Bing, Apple, DuckDuckGo, Yandex, Baidu.'],
  ['social', 'Social networks', 'Link previews when a page is shared on Facebook, Instagram, WhatsApp or Telegram.'],
  ['ai', 'AI assistants & MCP', 'ChatGPT, Claude and Perplexity opening pages for their users, and MCP tool calls to servers hosted on the sites. Never banned; the WAF "Block AI crawlers" switch still applies to them.'],
  ['cdn', 'CDN & website firewalls', 'Cloudflare, QUIC.cloud (LiteSpeed), Fastly, Bunny, CloudFront, Sucuri, Imperva: every visitor of a proxied site arrives from these addresses, so blocking one would take the site offline.'],
  ['monitor', 'Uptime monitors', 'Uptime checks, so a site is not reported down because the firewall blocked the monitor.'],
  ['payment', 'Payments', 'Order confirmations from Stripe and PayPal.'],
  ['wordpress', 'WordPress', 'Jetpack / WordPress.com, WordPress.org updates and WooCommerce.com.'],
  ['vendor', 'Hosting vendors', 'cPanel, LiteSpeed, CloudLinux / Imunify, Softaculous and Malware.Expert license and update servers.'],
  ['custom', 'Your list', 'Addresses you added below.'],
];

const sourceLabel = (s: string) =>
  s === 'official' ? 'official list' : s === 'dns' ? 'DNS' : s === 'builtin' ? 'built-in' : s === 'portal' ? 'portal' : '—';

/** Trusted services for every server (Overview » Trusted Services). */
export default function TrustedServices() {
  const { user } = useAuth();
  const admin = can(user, 'admin');
  const res = useApi<Resp>('/api/trusted');
  const [cfg, setCfg] = useState<Config | null>(null);
  const { run, busy } = useAction();
  useEffect(() => {
    if (res.data) setCfg(res.data.config);
  }, [res.data]);

  const dirty = useMemo(() => res.data && cfg && JSON.stringify(res.data.config) !== JSON.stringify(cfg), [res.data, cfg]);
  if (res.error && !res.data) return <ErrorBox message={res.error} />;
  if (!res.data || !cfg) return <PageLoader />;
  const d = res.data;
  const online = d.servers.filter((s) => s.online).length;
  const off = new Set(cfg.disabled);
  const toggle = (id: string, v: boolean) => {
    const n = new Set(cfg.disabled);
    if (v) n.delete(id);
    else n.add(id);
    setCfg({ ...cfg, disabled: Array.from(n).sort() });
  };
  const save = () =>
    run(
      () => api<{ version: number; pushed: number; offline: number }>('PUT', '/api/trusted', cfg).then((r) => (res.reload(), r)),
      (r) => `Saved (version ${r.version}): applied on ${r.pushed} online server${r.pushed === 1 ? '' : 's'}${r.offline ? `; ${r.offline} offline will follow when they reconnect` : ''}`,
    );

  return (
    <div className="space-y-5">
      <Breadcrumb items={['Overview', 'Trusted Services']} />
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="h-title flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-emerald-600" /> Trusted Services
          </h1>
          <p className="max-w-3xl text-sm text-slate-500">
            One list for all {d.servers.length} server{d.servers.length === 1 ? '' : 's'}. These services are never blocked by the firewall, IPDB, country blocks or
            automatic bans, so websites keep their SEO, previews, CDN, monitoring, payments and updates. Lists come from each provider's official source (or its
            network / DNS) and every server refreshes them daily.
          </p>
        </div>
        {admin && (
          <button className="btn-primary" disabled={busy || !dirty} onClick={save}>
            <Save className="h-4 w-4" /> {dirty ? 'Save & apply to all servers' : 'Saved'}
          </button>
        )}
      </div>

      <Card>
        <SettingRow title="Protect trusted services on all servers" desc="Recommended. Turn a single service off below if you want it treated like any other visitor.">
          <Toggle on={cfg.enabled} disabled={!admin || busy} onChange={(v) => setCfg({ ...cfg, enabled: v })} />
        </SettingRow>
        <p className="text-xs text-slate-500">
          {d.version ? `Version ${d.version}${d.updated_at ? `, saved ${new Date(d.updated_at).toLocaleString()}` : ''}.` : 'Not saved yet: each server keeps its own switches until you save here.'}{' '}
          {online} of {d.servers.length} server{d.servers.length === 1 ? '' : 's'} online.
        </p>
      </Card>

      {d.services.length === 0 ? (
        <Card title="Services">
          <p className="text-sm text-slate-500">No server answered: the list of services and their address counts appear when a server is online. You can still change the switches and your own list.</p>
        </Card>
      ) : (
        GROUPS.map(([g, label, desc]) => {
          const list = d.services.filter((s) => s.group === g);
          if (list.length === 0) return null;
          return (
            <Card key={g} title={label} desc={desc}>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[520px] text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-left text-xs uppercase text-slate-500">
                      <th className="py-2 pr-3">Service</th>
                      <th className="py-2 pr-3">Addresses</th>
                      <th className="py-2 pr-3">Source</th>
                      <th className="py-2 text-right">Trusted</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {list.map((t) => (
                      <tr key={t.id}>
                        <td className="py-2 pr-3 font-medium text-navy-900">
                          {t.name}
                          {t.error && (
                            <div className="text-xs font-normal text-amber-700" title={t.error}>
                              last update failed, previous list kept
                            </div>
                          )}
                        </td>
                        <td className="py-2 pr-3">{t.addresses}</td>
                        <td className="py-2 pr-3 text-xs text-slate-500">
                          {sourceLabel(t.source)}
                          {t.updated ? <div>{fmtTime(t.updated)}</div> : null}
                        </td>
                        <td className="py-2 text-right">
                          <Toggle on={!off.has(t.id)} disabled={!admin || busy || !cfg.enabled} onChange={(v) => toggle(t.id, v)} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          );
        })
      )}

      <Card title="Your trusted addresses" desc="Your own services for all servers: office IPs, your monitoring, your MCP or API clients, a partner's webhook sender. Wider than /8 is refused.">
        <ListEditor
          title="Addresses"
          items={cfg.custom}
          placeholder="IP or CIDR, e.g. 203.0.113.10 or 198.51.100.0/24"
          validate={isIPorCIDR}
          disabled={!admin || busy}
          onChange={(v) => setCfg({ ...cfg, custom: v })}
        />
      </Card>

      {d.source && (
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500">
          <span>Address counts from {d.source.hostname}; every server downloads the same lists.</span>
          {admin && (
            <button
              className="btn-outline"
              disabled={busy}
              onClick={() => run(() => agentCall(d.source!.id, 'trusted.refresh').then(res.reload), 'Lists updated on ' + d.source!.hostname)}
            >
              <RefreshCw className="h-4 w-4" /> Update lists now
            </button>
          )}
        </div>
      )}
    </div>
  );
}
