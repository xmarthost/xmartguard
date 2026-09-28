import { useState, type ReactNode } from 'react';
import { Check, Copy, Inbox, Loader2 } from 'lucide-react';

/** xPGuard wordmark: the XP icon with "xPGuard" set in text, so it stays
 *  readable on the dark header (light) and on white pages. `full` shows the
 *  complete logo artwork with its tagline (login page). */
export function Logo({ light = false, full = false }: { light?: boolean; full?: boolean }) {
  if (full) return <img src="/xpguard-logo.png" alt="xPGuard — Proactive Server Security" className="h-28 w-auto" />;
  return (
    <div className="flex items-center gap-2.5">
      <img src="/xpguard-mark.png" alt="" className="h-8 w-auto" />
      <span className="flex flex-col leading-none">
        <span className={`text-[21px] font-extrabold tracking-tight ${light ? 'text-white' : 'text-navy-900'}`}>
          <span className="bg-gradient-to-r from-amber-400 via-orange-500 to-red-500 bg-clip-text text-transparent">xP</span>Guard
        </span>
        <span className={`mt-1 text-[8.5px] font-semibold tracking-[0.24em] uppercase ${light ? 'text-white/70' : 'text-slate-400'}`}>Proactive Server Security</span>
      </span>
    </div>
  );
}

export function Spinner({ className = '' }: { className?: string }) {
  return <Loader2 className={`h-5 w-5 animate-spin text-navy-600 ${className}`} />;
}

/**
 * Full-page loader: the xPGuard logo with a light sweeping through it,
 * shown only while a page loads its data.
 */
export function PageLoader() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center" role="status" aria-label="Loading">
      <div className="xg-loader flex items-center gap-3">
        <span className="xg-loader-mark relative h-14 w-14">
          <img src="/xpguard-icon.png" alt="" className="h-14 w-14 object-contain" />
          <span className="xg-loader-sweep absolute inset-0" />
        </span>
        <span className="xg-loader-word text-[34px] leading-none font-extrabold tracking-tight">xPGuard</span>
      </div>
    </div>
  );
}

/** Small loader for a section inside a page (cards, tables). */
export function SectionLoader() {
  return (
    <div className="flex h-40 items-center justify-center">
      <Spinner className="h-7 w-7" />
    </div>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{message}</div>;
}

export function Empty({ text = 'No records to display', children }: { text?: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-slate-500">
      <Inbox className="h-10 w-10 text-slate-300" />
      <p className="text-sm">{text}</p>
      {children}
    </div>
  );
}

export function StatusDot({ online }: { online: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${online ? 'text-green-600' : 'text-slate-400'}`}>
      <span className={`h-2 w-2 rounded-full ${online ? 'bg-green-500' : 'bg-slate-300'}`} />
      {online ? 'Online' : 'Offline'}
    </span>
  );
}

export function CopyBox({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-stretch overflow-hidden rounded-lg bg-navy-950">
      <code className="flex-1 overflow-x-auto px-4 py-3 font-mono text-sm break-all whitespace-pre-wrap text-green-300">{text}</code>
      <button
        type="button"
        className="flex items-center gap-1 bg-navy-800 px-3 text-sm text-white hover:bg-navy-700"
        onClick={async () => {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }}
      >
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
}

export function Bar({ value, className = 'bg-green-500' }: { value: number; className?: string }) {
  return (
    <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-200">
      <div className={`h-full rounded-full ${className}`} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
    </div>
  );
}

export function Breadcrumb({ items }: { items: string[] }) {
  return (
    <div className="mb-1 text-sm text-slate-400">
      {items.map((it, i) => (
        <span key={i}>
          {i > 0 && <span className="mx-2">›</span>}
          <span className={i === items.length - 1 ? 'text-navy-800' : ''}>{it}</span>
        </span>
      ))}
    </div>
  );
}

export function StatCard({ icon, value, label, accent = 'text-navy-900' }: { icon: ReactNode; value: ReactNode; label: string; accent?: string }) {
  return (
    <div className="card flex items-center gap-4 p-5">
      <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-navy-100 text-navy-800">{icon}</div>
      <div>
        <div className={`text-3xl font-semibold ${accent}`}>{value}</div>
        <div className="text-sm text-slate-500">{label}</div>
      </div>
    </div>
  );
}

export function ComingSoon({ title, milestone }: { title: string; milestone: string }) {
  return (
    <div className="card mx-auto mt-10 max-w-xl p-10 text-center">
      <h2 className="text-xl font-semibold text-navy-900">{title}</h2>
      <p className="mt-2 text-slate-500">This module is being built and will be available in {milestone}.</p>
    </div>
  );
}
