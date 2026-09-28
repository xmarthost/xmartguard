import { useEffect, useRef, useState } from 'react';
import { Check, Moon, Palette, Save, Sun } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Breadcrumb, PageLoader } from '../components/ui';
import { Card, useAction } from '../components/controls';
import { THEMES, applyAppearance, resolveTheme, type Appearance, type ThemePreset } from '../theme';

/** A small picture of the portal in a theme: header, sidebar, a card. */
function Preview({ t }: { t: ThemePreset }) {
  const dark = t.mode === 'dark';
  const card = dark ? '#111827' : '#ffffff';
  const line = dark ? '#273145' : '#e5e7eb';
  return (
    <div className="overflow-hidden rounded-lg ring-1 ring-black/10" style={{ background: t.page }}>
      <div className="flex h-5 items-center gap-1 px-2" style={{ background: t.scale[1] }}>
        <span className="h-2 w-2 rounded-sm bg-white/90" />
        <span className="h-1.5 w-10 rounded bg-white/70" />
        <span className="ml-auto h-2 w-2 rounded-full" style={{ background: t.accent }} />
      </div>
      <div className="flex h-20">
        <div className="flex w-6 flex-col items-center gap-1.5 pt-2" style={{ background: `linear-gradient(${t.scale[1]}, ${t.scale[3]})` }}>
          <span className="h-1.5 w-3 rounded bg-white/80" />
          <span className="h-1.5 w-3 rounded bg-white/40" />
          <span className="h-1.5 w-3 rounded bg-white/40" />
        </div>
        <div className="flex-1 space-y-1.5 p-2">
          <div className="h-2 w-16 rounded" style={{ background: dark ? '#e2e8f0' : t.scale[1] }} />
          <div className="rounded p-1.5" style={{ background: card, border: `1px solid ${line}` }}>
            <div className="h-1.5 w-full rounded" style={{ background: line }} />
            <div className="mt-1 h-1.5 w-2/3 rounded" style={{ background: line }} />
            <div className="mt-1.5 flex gap-1">
              <span className="h-2.5 w-8 rounded" style={{ background: t.scale[2] }} />
              <span className="h-2.5 w-5 rounded" style={{ background: t.accent }} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function AppearancePage() {
  const { user } = useAuth();
  const admin = can(user, 'admin');
  const [saved, setSaved] = useState<Appearance | null>(null);
  // null until the saved appearance is loaded: nothing is applied (or
  // remembered in the browser) before that.
  const [cur, setCur] = useState<Appearance | null>(null);
  const { run, busy } = useAction();

  useEffect(() => {
    api<{ appearance: Appearance }>('GET', '/api/appearance').then((r) => {
      setSaved(r.appearance);
      setCur(r.appearance);
    });
  }, []);
  // Preview live; leaving the page without saving restores the saved theme.
  // (Only on leaving: restoring whenever "saved" changed put the old theme
  // back right after a save.)
  const savedRef = useRef<Appearance | null>(null);
  savedRef.current = saved;
  useEffect(() => void (cur && applyAppearance(cur)), [cur]);
  useEffect(() => () => void (savedRef.current && applyAppearance(savedRef.current)), []);

  if (!cur) return <PageLoader />;
  const pick = (t: ThemePreset) => setCur({ theme: t.id, mode: t.mode });
  const custom = cur.theme === 'custom';
  const dirty = saved && JSON.stringify(saved) !== JSON.stringify(cur);
  const save = async () => {
    const r = await run(() => api<{ appearance: Appearance }>('PUT', '/api/appearance', cur), 'Appearance saved for every user');
    if (r) setSaved(r.appearance);
  };

  return (
    <div className="mx-auto max-w-6xl space-y-5 pb-24">
      <Breadcrumb items={['Appearance']} />
      <div>
        <h1 className="h-title flex items-center gap-2">
          <Palette className="h-6 w-6" /> Appearance
        </h1>
        <p className="mt-1 text-sm text-slate-500">Ready-made colour and sidebar combinations, light and dark. The theme you save applies to every user of this portal.</p>
      </div>

      <Card title="Themes" desc="Click a theme to preview it on this page.">
        <div className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {THEMES.map((t) => {
            const on = cur.theme === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => pick(t)}
                className={`rounded-xl border p-3 text-left transition hover:shadow-md ${on ? 'border-navy-600 ring-2 ring-navy-600' : 'border-slate-200'}`}
              >
                <Preview t={t} />
                <div className="mt-2 flex items-center justify-between text-sm">
                  <span className="font-medium text-navy-900">{t.name}</span>
                  <span className="flex items-center gap-1 text-xs text-slate-500">
                    {t.mode === 'dark' ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5" />}
                    {on && <Check className="h-4 w-4 text-emerald-600" />}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </Card>

      <Card title="Custom" desc="Your own sidebar colour and accent, in light or dark mode.">
        <div className="mt-3 grid items-end gap-4 sm:grid-cols-[auto_auto_auto_1fr]">
          <label className="text-sm">
            <span className="label">Sidebar &amp; header</span>
            <input
              type="color"
              className="h-10 w-20 cursor-pointer rounded border border-slate-300"
              value={cur.sidebar ?? '#172155'}
              onChange={(e) => setCur({ theme: 'custom', mode: cur.mode, sidebar: e.target.value, accent: cur.accent ?? '#22c55e' })}
            />
          </label>
          <label className="text-sm">
            <span className="label">Accent</span>
            <input
              type="color"
              className="h-10 w-20 cursor-pointer rounded border border-slate-300"
              value={cur.accent ?? '#22c55e'}
              onChange={(e) => setCur({ theme: 'custom', mode: cur.mode, sidebar: cur.sidebar ?? '#172155', accent: e.target.value })}
            />
          </label>
          <div className="text-sm">
            <span className="label">Mode</span>
            <div className="inline-flex overflow-hidden rounded-lg border border-slate-300">
              {(['light', 'dark'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  className={`flex items-center gap-1 px-3 py-2 ${cur.mode === m ? 'bg-navy-800 text-white' : 'text-slate-600'}`}
                  onClick={() => setCur({ theme: 'custom', mode: m, sidebar: cur.sidebar ?? resolveTheme(cur).scale[1], accent: cur.accent ?? resolveTheme(cur).accent })}
                >
                  {m === 'dark' ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />} {m}
                </button>
              ))}
            </div>
          </div>
          {custom && (
            <div className="w-48">
              <Preview t={resolveTheme(cur)} />
            </div>
          )}
        </div>
      </Card>

      {admin && dirty && (
        <div className="fixed inset-x-0 bottom-0 z-30 border-t border-slate-200 bg-white/95 px-4 py-3 shadow-lg backdrop-blur">
          <div className="mx-auto flex max-w-6xl items-center justify-end gap-3">
            <span className="text-sm text-slate-500">Previewing — not saved</span>
            <button className="btn-outline" onClick={() => saved && setCur(saved)}>
              Discard
            </button>
            <button className="btn-primary" disabled={busy} onClick={save}>
              <Save className="h-4 w-4" /> Save for everyone
            </button>
          </div>
        </div>
      )}
      {!admin && <p className="text-sm text-slate-500">Only administrators can change the portal's appearance.</p>}
    </div>
  );
}
