/**
 * Portal themes. The layout uses the navy scale (sidebar, header, buttons,
 * headings) and "page" (background); a theme sets those CSS variables. Dark
 * themes also switch cards, text and borders (see index.css, [data-mode]).
 */
export interface Appearance {
  theme: string;
  mode: 'light' | 'dark';
  sidebar?: string;
  accent?: string;
}

export interface ThemePreset {
  id: string;
  name: string;
  mode: 'light' | 'dark';
  /** navy 950..600 + 100, page background */
  scale: [string, string, string, string, string, string];
  page: string;
  accent: string;
}

export const THEMES: ThemePreset[] = [
  { id: 'navy', name: 'Navy (default)', mode: 'light', scale: ['#0f1640', '#172155', '#1d2b64', '#26377a', '#34479a', '#e6e9f5'], page: '#f3f4f7', accent: '#22c55e' },
  { id: 'ocean', name: 'Ocean', mode: 'light', scale: ['#082f49', '#0c4a6e', '#075985', '#0369a1', '#0284c7', '#e0f2fe'], page: '#f1f7fb', accent: '#06b6d4' },
  { id: 'emerald', name: 'Emerald', mode: 'light', scale: ['#022c22', '#064e3b', '#065f46', '#047857', '#059669', '#d1fae5'], page: '#f2f8f5', accent: '#10b981' },
  { id: 'violet', name: 'Royal Violet', mode: 'light', scale: ['#1e0a45', '#2e1065', '#4c1d95', '#5b21b6', '#6d28d9', '#ede9fe'], page: '#f6f4fb', accent: '#a855f7' },
  { id: 'crimson', name: 'Crimson', mode: 'light', scale: ['#3b0712', '#4c0519', '#881337', '#9f1239', '#be123c', '#ffe4e6'], page: '#faf4f5', accent: '#f43f5e' },
  { id: 'slate', name: 'Slate & Amber', mode: 'light', scale: ['#020617', '#0f172a', '#1e293b', '#334155', '#475569', '#e2e8f0'], page: '#f4f5f7', accent: '#f59e0b' },
  { id: 'midnight', name: 'Midnight (dark)', mode: 'dark', scale: ['#05070f', '#0b1020', '#1e3a8a', '#1d4ed8', '#3b82f6', '#1e293b'], page: '#0b0f19', accent: '#22c55e' },
  { id: 'graphite', name: 'Graphite (dark)', mode: 'dark', scale: ['#09090b', '#18181b', '#3f3f46', '#52525b', '#71717a', '#27272a'], page: '#0f0f11', accent: '#f97316' },
  { id: 'deep-teal', name: 'Deep Teal (dark)', mode: 'dark', scale: ['#021a1f', '#042f36', '#0f766e', '#0d9488', '#14b8a6', '#134e4a'], page: '#061417', accent: '#2dd4bf' },
];

/** Mixes a #rrggbb colour with black (t<0) or white (t>0). */
export function shade(hex: string, t: number): string {
  const n = parseInt(hex.slice(1), 16);
  const c = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => Math.round(t < 0 ? v * (1 + t) : v + (255 - v) * t));
  return '#' + c.map((v) => v.toString(16).padStart(2, '0')).join('');
}

/** The preset a saved appearance stands for (custom colours become one). */
export function resolveTheme(a: Appearance): ThemePreset {
  if (a.theme === 'custom' && a.sidebar && /^#[0-9a-f]{6}$/i.test(a.sidebar)) {
    const b = a.sidebar;
    const dark = a.mode === 'dark';
    return {
      id: 'custom',
      name: 'Custom',
      mode: a.mode,
      scale: [shade(b, -0.45), b, shade(b, 0.12), shade(b, 0.22), shade(b, 0.35), dark ? shade(b, -0.2) : shade(b, 0.88)],
      page: dark ? '#0c0f16' : shade(b, 0.95),
      accent: a.accent && /^#[0-9a-f]{6}$/i.test(a.accent) ? a.accent : '#22c55e',
    };
  }
  return THEMES.find((t) => t.id === a.theme) ?? THEMES[0];
}

const KEY = 'xg-appearance';

export function applyAppearance(a: Appearance) {
  const t = resolveTheme(a);
  const root = document.documentElement;
  const names = ['950', '900', '800', '700', '600', '100'];
  t.scale.forEach((v, i) => root.style.setProperty(`--color-navy-${names[i]}`, v));
  root.style.setProperty('--color-page', t.page);
  root.style.setProperty('--xg-accent', t.accent);
  root.dataset.mode = t.mode;
  root.style.colorScheme = t.mode;
  try {
    localStorage.setItem(KEY, JSON.stringify(a));
  } catch {
    /* storage unavailable */
  }
}

/** Applies the last known appearance at start-up (no flash of the default). */
export function applyCachedAppearance() {
  try {
    const s = localStorage.getItem(KEY);
    if (s) applyAppearance(JSON.parse(s));
  } catch {
    /* ignore */
  }
}
