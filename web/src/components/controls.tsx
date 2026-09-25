import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { ChevronLeft, ChevronRight, Plus, Star, Trash2, X } from 'lucide-react';
import { api } from '../api';

// ------------------------------------------------------------------ agent calls

/** Calls an agent action through the portal proxy. */
export function agentCall<T = any>(serverId: string, action: string, params: unknown = {}): Promise<T> {
  return api<T>('POST', `/api/servers/${serverId}/agent/${action}`, params);
}

/** Loads an agent action, optionally polling. */
export function useAgent<T>(serverId: string | undefined, action: string, params: unknown = {}, intervalMs?: number) {
  const key = JSON.stringify(params);
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    if (!serverId) return;
    try {
      setData(await agentCall<T>(serverId, action, JSON.parse(key)));
      setError(null);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serverId, action, key]);
  useEffect(() => {
    setLoading(true);
    load();
    if (!intervalMs) return;
    const t = setInterval(load, intervalMs);
    return () => clearInterval(t);
  }, [load, intervalMs]);
  return { data, error, loading, reload: load, setData };
}

// ------------------------------------------------------------------ toasts

type Toast = { id: number; kind: 'ok' | 'err'; text: string };
const ToastCtx = createContext<(kind: 'ok' | 'err', text: string) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((kind: 'ok' | 'err', text: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === 'err' ? 7000 : 3500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="fixed right-4 bottom-4 z-50 flex max-w-sm flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} className={`rounded-lg px-4 py-3 text-sm text-white shadow-lg ${t.kind === 'ok' ? 'bg-green-600' : 'bg-red-600'}`}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

/** Runs an async action with success/error toasts; returns its result or undefined. */
export function useAction() {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = useCallback(
    async <T,>(fn: () => Promise<T>, okText?: string | ((r: T) => string)): Promise<T | undefined> => {
      setBusy(true);
      try {
        const r = await fn();
        if (okText) toast('ok', typeof okText === 'function' ? okText(r) : okText);
        return r;
      } catch (e: any) {
        toast('err', e.message || 'Something went wrong');
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [toast],
  );
  return { run, busy };
}

// ------------------------------------------------------------------ inputs

export function Toggle({ on, onChange, disabled }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      disabled={disabled}
      onClick={() => onChange(!on)}
      className={`inline-flex h-7 w-16 shrink-0 items-center justify-between rounded-full border px-1.5 text-[10px] font-semibold transition disabled:opacity-50 ${
        on ? 'border-green-200 bg-white text-slate-600' : 'border-red-200 bg-white text-slate-500'
      }`}
    >
      {on ? (
        <>
          <span className="pl-1">ON</span>
          <span className="h-5 w-5 rounded-full bg-green-500" />
        </>
      ) : (
        <>
          <span className="h-5 w-5 rounded-full bg-red-500" />
          <span className="pr-1">OFF</span>
        </>
      )}
    </button>
  );
}

export function Recommended() {
  return (
    <span className="inline-flex items-center gap-1 text-xs text-orange-500">
      <Star className="h-3 w-3" /> recommended
    </span>
  );
}

/** A labelled setting row with a control on the right. */
export function SettingRow({ title, desc, children, recommended }: { title: string; desc?: string; children: ReactNode; recommended?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-6 border-b border-slate-100 py-4 last:border-0">
      <div>
        <div className="font-medium text-navy-900">{title}</div>
        {desc && <div className="mt-0.5 text-sm text-slate-500">{desc}</div>}
      </div>
      <div className="flex shrink-0 items-center gap-3">
        {recommended && <Recommended />}
        {children}
      </div>
    </div>
  );
}

/** Editable string list with an input + Add button, like the portal's whitelist editors. */
export function ListEditor({
  title, desc, items, onChange, placeholder = 'Type here', options, empty = 'Nothing added yet', validate, disabled,
}: {
  title: string;
  desc?: string;
  items: string[];
  onChange: (items: string[]) => void | Promise<void>;
  placeholder?: string;
  options?: string[];
  empty?: string;
  validate?: (v: string) => string | null;
  disabled?: boolean;
}) {
  const [value, setValue] = useState('');
  const [err, setErr] = useState('');
  const add = () => {
    const vals = value.split(/[\n,]+/).map((v) => v.trim()).filter(Boolean);
    if (!vals.length) return;
    for (const v of vals) {
      const e = validate?.(v);
      if (e) {
        setErr(e);
        return;
      }
    }
    setErr('');
    setValue('');
    onChange([...items, ...vals.filter((v) => !items.includes(v))]);
  };
  return (
    <div className="border-b border-slate-100 py-4 last:border-0">
      <div className="font-medium text-navy-900">{title}</div>
      {desc && <div className="mb-3 text-sm text-slate-500">{desc}</div>}
      <div className="flex gap-3">
        {options ? (
          <select className="input" value={value} onChange={(e) => setValue(e.target.value)} disabled={disabled}>
            <option value="">Select…</option>
            {options.filter((o) => !items.includes(o)).map((o) => (
              <option key={o} value={o}>{o}</option>
            ))}
          </select>
        ) : (
          <input
            className="input"
            placeholder={placeholder}
            value={value}
            disabled={disabled}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), add())}
          />
        )}
        <button type="button" className="btn-primary px-6" onClick={add} disabled={disabled || !value.trim()}>
          <Plus className="h-4 w-4" /> Add
        </button>
      </div>
      {err && <div className="mt-2 text-sm text-red-600">{err}</div>}
      <div className="mt-3">
        {items.length === 0 ? (
          <div className="text-sm text-slate-400">{empty}</div>
        ) : (
          items.map((it) => (
            <div key={it} className="flex items-center justify-between border-b border-slate-100 py-2 text-sm last:border-0">
              <span className="font-mono text-slate-700">{it}</span>
              <button type="button" className="text-slate-400 hover:text-red-600" onClick={() => onChange(items.filter((x) => x !== it))} disabled={disabled} aria-label={`remove ${it}`}>
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { v: T; l: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex gap-1 rounded-lg bg-slate-100 p-1">
      {tabs.map((t) => (
        <button
          key={t.v}
          type="button"
          onClick={() => onChange(t.v)}
          className={`rounded-md px-3 py-1.5 text-sm ${value === t.v ? 'bg-white font-medium text-navy-900 shadow-sm' : 'text-slate-500 hover:text-navy-800'}`}
        >
          {t.l}
        </button>
      ))}
    </div>
  );
}

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 p-4" onClick={onClose}>
      <div className={`card max-h-[90vh] w-full overflow-y-auto p-6 ${wide ? 'max-w-4xl' : 'max-w-2xl'}`} onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-xl font-semibold text-navy-900">{title}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-navy-800" aria-label="close">
            <X />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Pager({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (offset: number) => void }) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  return (
    <div className="flex items-center justify-end gap-3 pt-4 text-sm text-slate-500">
      <span>
        {from} – {to} of {total}
      </span>
      <button className="rounded p-1 hover:bg-slate-100 disabled:opacity-30" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))} aria-label="previous">
        <ChevronLeft className="h-4 w-4" />
      </button>
      <button className="rounded p-1 hover:bg-slate-100 disabled:opacity-30" disabled={to >= total} onClick={() => onChange(offset + limit)} aria-label="next">
        <ChevronRight className="h-4 w-4" />
      </button>
    </div>
  );
}

const BADGE: Record<string, string> = {
  completed: 'bg-green-100 text-green-700', running: 'bg-blue-100 text-blue-700', queued: 'bg-slate-100 text-slate-600',
  failed: 'bg-red-100 text-red-700', stopped: 'bg-amber-100 text-amber-700',
  detected: 'bg-red-100 text-red-700', quarantined: 'bg-navy-600 text-white', disabled: 'bg-amber-100 text-amber-800',
  restored: 'bg-slate-100 text-slate-600', deleted: 'bg-slate-200 text-slate-600', ignored: 'bg-slate-100 text-slate-500',
  blocked: 'bg-navy-600 text-white', unblocked: 'bg-slate-100 text-slate-600', expired: 'bg-slate-100 text-slate-500',
  virus: 'bg-red-50 text-red-700', suspicious: 'bg-amber-50 text-amber-700', binary: 'bg-purple-50 text-purple-700',
};

export function Badge({ value }: { value: string }) {
  return <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${BADGE[value] ?? 'bg-slate-100 text-slate-600'}`}>{value}</span>;
}

export function fmtTime(ts: number | undefined | null): string {
  if (!ts) return '–';
  return new Date(ts * 1000).toLocaleString();
}

export function Card({ title, desc, children, right }: { title?: string; desc?: string; children: ReactNode; right?: ReactNode }) {
  return (
    <div className="card p-6">
      {(title || right) && (
        <div className="mb-2 flex items-start justify-between gap-4">
          <div>
            {title && <h2 className="text-lg font-semibold text-navy-900">{title}</h2>}
            {desc && <p className="text-sm text-slate-500">{desc}</p>}
          </div>
          {right}
        </div>
      )}
      {children}
    </div>
  );
}

export function isIPorCIDR(v: string): string | null {
  const ip4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  const ip6 = /^[0-9a-fA-F:]+(\/\d{1,3})?$/;
  return ip4.test(v) || (v.includes(':') && ip6.test(v)) ? null : `${v} is not a valid IP address or CIDR`;
}
