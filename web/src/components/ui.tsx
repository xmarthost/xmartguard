import { useState, type ReactNode } from 'react';
import { Check, Copy, Inbox, Loader2 } from 'lucide-react';

export function Logo({ light = false }: { light?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <img src="/favicon.svg" alt="" className="h-8 w-8" />
      <span className={`text-xl font-bold tracking-tight ${light ? 'text-white' : 'text-navy-900'}`}>
        XMart<span className="text-green-400">Guard</span>
      </span>
    </div>
  );
}

export function Spinner({ className = '' }: { className?: string }) {
  return <Loader2 className={`h-5 w-5 animate-spin text-navy-600 ${className}`} />;
}

export function PageLoader() {
  return (
    <div className="flex h-64 items-center justify-center">
      <Spinner className="h-8 w-8" />
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
