/**
 * Portal themes. The layout uses the navy scale (sidebar, header, buttons,
 * headings) and "page" (background); a theme sets those CSS variables. Dark
 * themes also switch cards, text and borders (see index.css, [data-mode]).
 */
export type UiStyle = 'classic' | 'modern';

export interface Appearance {
  theme: string;
  mode: 'light' | 'dark';
  sidebar?: string;
  accent?: string;
  /** Page style: classic (dark sidebar, default) or modern (light sidebar). */
  style?: UiStyle;
}

export const STYLES: { id: UiStyle; name: string; desc: string }[] = [
  { id: 'classic', name: 'Classic', desc: 'Dark sidebar that opens on hover, coloured header (the default).' },
  { id: 'modern', name: 'Modern', desc: 'Light sidebar with labels, white header with search, tinted icon cards and small charts.' },
];

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
const MODE_KEY = 'xg-mode';

// The style in use, for components that render differently per style.
let curStyle: UiStyle = 'classic';
const listeners = new Set<() => void>();
export function getUiStyle(): UiStyle {
  return curStyle;
}
export function subscribeUiStyle(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** This browser's light/dark choice (the Modern header's moon button); ''
 *  follows the portal's theme. */
export function getModeOverride(): '' | 'light' | 'dark' {
  try {
    const v = localStorage.getItem(MODE_KEY);
    return v === 'light' || v === 'dark' ? v : '';
  } catch {
    return '';
  }
}
export function setModeOverride(m: '' | 'light' | 'dark') {
  try {
    if (m) localStorage.setItem(MODE_KEY, m);
    else localStorage.removeItem(MODE_KEY);
  } catch {
    /* storage unavailable */
  }
  if (last) applyAppearance(last);
}

let last: Appearance | null = null;

export function applyAppearance(a: Appearance) {
  last = a;
  const t = resolveTheme(a);
  const style: UiStyle = a.style === 'modern' ? 'modern' : 'classic';
  const root = document.documentElement;
  const names = ['950', '900', '800', '700', '600', '100'];
  t.scale.forEach((v, i) => root.style.setProperty(`--color-navy-${names[i]}`, v));
  const override = style === 'modern' ? getModeOverride() : '';
  const mode = override || t.mode;
  let page = t.page;
  if (style === 'modern') {
    // Modern: a cool light grey page, or the theme's dark page; its buttons
    // and links use a bright primary (blue on the default theme).
    page = mode === 'dark' ? (t.mode === 'dark' ? t.page : '#0b1120') : t.mode === 'dark' ? '#f5f7fb' : t.id === 'navy' ? '#f5f7fb' : t.page;
    root.style.setProperty('--xg-primary', t.id === 'navy' ? '#2563eb' : t.mode === 'dark' ? t.scale[4] : t.scale[3]);
  } else {
    root.style.removeProperty('--xg-primary');
  }
  root.style.setProperty('--color-page', page);
  root.style.setProperty('--xg-accent', t.accent);
  root.dataset.mode = mode;
  root.dataset.style = style;
  root.style.colorScheme = mode;
  if (style !== curStyle) {
    curStyle = style;
    listeners.forEach((fn) => fn());
  }
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
