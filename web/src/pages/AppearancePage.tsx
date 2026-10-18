import { useEffect, useRef, useState } from 'react';
import { Check, Moon, Palette, Save, Sun } from 'lucide-react';
import { api } from '../api';
import { can, useAuth } from '../auth';
import { Breadcrumb, PageLoader } from '../components/ui';
import { Card, useAction } from '../components/controls';
import { THEMES, applyAppearance, resolveTheme, type Appearance, type ThemePreset } from '../theme';

/** A small picture of the portal in a theme: sidebar, header, cards. */
function Preview({ t }: { t: ThemePreset }) {
  const dark = t.mode === 'dark';
  const card = dark ? '#111827' : '#ffffff';
  const line = dark ? '#273145' : '#e5e7eb';
  const primary = t.id === 'navy' || t.id === 'midnight' ? '#2563eb' : dark ? t.scale[4] : t.scale[3];
  return (
    <div className="overflow-hidden rounded-lg ring-1 ring-black/10" style={{ background: dark ? t.page : '#f5f7fb' }}>
      <div className="flex h-[104px]">
        <div className="flex w-14 flex-col gap-1.5 p-1.5" style={{ background: card, borderRight: `1px solid ${line}` }}>
          <span className="mb-1 flex items-center gap-0.5">
            <span className="h-2.5 w-2.5 rounded-sm bg-orange-400" />
            <span className="h-1.5 w-6 rounded" style={{ background: dark ? '#e2e8f0' : '#334155' }} />
          </span>
          <span className="h-2 rounded" style={{ background: primary, opacity: 0.25 }} />
          {[0, 1, 2].map((i) => (
            <span key={i} className="h-1.5 w-9 rounded" style={{ background: line }} />
          ))}
        </div>
        <div className="flex-1">
          <div className="flex h-6 items-center gap-1 px-2" style={{ background: card, borderBottom: `1px solid ${line}` }}>
            <span className="h-2.5 w-16 rounded" style={{ background: line }} />
            <span className="ml-auto h-2.5 w-2.5 rounded-full" style={{ background: t.accent }} />
          </div>
          <div className="space-y-1.5 p-2">
            <div className="grid grid-cols-3 gap-1">
              {[0, 1, 2].map((i) => (
                <div key={i} className="h-6 rounded" style={{ background: card, border: `1px solid ${line}` }} />
              ))}
            </div>
            <div className="flex h-8 items-end gap-1 rounded p-1" style={{ background: card, border: `1px solid ${line}` }}>
              <span className="h-2.5 w-8 rounded" style={{ background: primary }} />
              <span className="h-2.5 w-5 rounded" style={{ background: t.accent }} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

const custom = (a: Appearance) => a.theme === 'custom' && !!a.sidebar;

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
  // Retired presets show as the Light or Dark they now look like.
  const shown = custom(cur) ? 'custom' : resolveTheme(cur).id;
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
        <p className="mt-1 text-sm text-slate-500">Light or dark, or your own brand colour. What you save applies to every user of this portal; each user can still switch light/dark for themselves with the moon button in the header.</p>
      </div>

      <Card title="Theme" desc="Click to preview it on this page.">
        <div className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {THEMES.map((t) => {
            const on = shown === t.id;
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

      <Card title="Brand colour" desc="Your own colour for buttons and links, and an accent, in light or dark mode.">
        <div className="mt-3 grid items-end gap-4 sm:grid-cols-[auto_auto_auto_1fr]">
          <label className="text-sm">
            <span className="label">Brand colour</span>
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
          {shown === 'custom' && (
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
