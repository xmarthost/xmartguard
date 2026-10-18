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
  /** Old saves may say "classic": the portal has one style, Modern. */
  style?: string;
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

// Light and dark; any other colour is a custom brand colour. Saves of the
// retired presets (ocean, emerald, graphite…) show as Light or Dark.
export const THEMES: ThemePreset[] = [
  { id: 'navy', name: 'Light', mode: 'light', scale: ['#0f1640', '#172155', '#1d2b64', '#26377a', '#34479a', '#e6e9f5'], page: '#f3f4f7', accent: '#22c55e' },
  { id: 'midnight', name: 'Dark', mode: 'dark', scale: ['#05070f', '#0b1020', '#1e3a8a', '#1d4ed8', '#3b82f6', '#1e293b'], page: '#0b0f19', accent: '#22c55e' },
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
  return THEMES.find((t) => t.id === a.theme) ?? (a.mode === 'dark' ? THEMES[1] : THEMES[0]);
}

const KEY = 'xg-appearance';
const MODE_KEY = 'xg-mode';

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
  const root = document.documentElement;
  const names = ['950', '900', '800', '700', '600', '100'];
  t.scale.forEach((v, i) => root.style.setProperty(`--color-navy-${names[i]}`, v));
  const override = getModeOverride();
  const mode = override || t.mode;
  // A cool light grey page, or the theme's dark page; buttons and links use
  // a bright primary (blue on the default themes).
  const page = mode === 'dark' ? (t.mode === 'dark' ? t.page : '#0b1120') : t.mode === 'dark' ? '#f5f7fb' : t.id === 'navy' ? '#f5f7fb' : t.page;
  const blue = t.id === 'navy' || t.id === 'midnight';
  root.style.setProperty('--xg-primary', blue ? '#2563eb' : t.mode === 'dark' ? t.scale[4] : t.scale[3]);
  root.style.setProperty('--color-page', page);
  root.style.setProperty('--xg-accent', t.accent);
  root.dataset.mode = mode;
  root.dataset.style = 'modern';
  root.style.colorScheme = mode;
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
