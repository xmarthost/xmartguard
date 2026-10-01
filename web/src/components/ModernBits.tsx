import { useId, type ReactNode } from 'react';

/** Colours of the Modern style's tinted icon tiles and charts. */
export const TONES = {
  red: { bg: 'bg-red-50', fg: 'text-red-500', line: '#ef4444' },
  blue: { bg: 'bg-blue-50', fg: 'text-blue-600', line: '#3b82f6' },
  green: { bg: 'bg-green-50', fg: 'text-green-600', line: '#22c55e' },
  orange: { bg: 'bg-orange-50', fg: 'text-orange-500', line: '#f97316' },
  purple: { bg: 'bg-violet-50', fg: 'text-violet-500', line: '#8b5cf6' },
  sky: { bg: 'bg-sky-50', fg: 'text-sky-600', line: '#0ea5e9' },
} as const;
export type Tone = keyof typeof TONES;

/** A rounded square with a tinted background and an icon. */
export function IconTile({ tone, children, size = 'md' }: { tone: Tone; children: ReactNode; size?: 'sm' | 'md' | 'lg' }) {
  const t = TONES[tone];
  const box = size === 'lg' ? 'h-14 w-14 rounded-2xl [&>svg]:h-7 [&>svg]:w-7' : size === 'sm' ? 'h-9 w-9 rounded-xl [&>svg]:h-[18px] [&>svg]:w-[18px]' : 'h-11 w-11 rounded-xl [&>svg]:h-5 [&>svg]:w-5';
  return <span className={`xg-tile flex shrink-0 items-center justify-center ${box} ${t.bg} ${t.fg}`}>{children}</span>;
}

/** A smooth sparkline with a soft fill; flat when there is no data. */
export function Sparkline({ points, tone, className = 'h-10 w-full' }: { points: number[]; tone: Tone; className?: string }) {
  const id = useId().replace(/:/g, '');
  const w = 200;
  const h = 44;
  const pts = points.length > 1 ? points : [0, 0];
  const max = Math.max(1, ...pts);
  const step = w / (pts.length - 1);
  const xy = pts.map((v, i) => [i * step, h - 6 - (v / max) * (h - 14)] as const);
  // Catmull-Rom to Bezier: a smooth line through every point.
  let d = `M${xy[0][0].toFixed(1)},${xy[0][1].toFixed(1)}`;
  for (let i = 0; i < xy.length - 1; i++) {
    const p0 = xy[i - 1] ?? xy[i];
    const p1 = xy[i];
    const p2 = xy[i + 1];
    const p3 = xy[i + 2] ?? p2;
    const c1 = [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6];
    const c2 = [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6];
    d += ` C${c1[0].toFixed(1)},${c1[1].toFixed(1)} ${c2[0].toFixed(1)},${c2[1].toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  const c = TONES[tone].line;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className={className} aria-hidden>
      <defs>
        <linearGradient id={`g${id}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={c} stopOpacity={0.22} />
          <stop offset="100%" stopColor={c} stopOpacity={0} />
        </linearGradient>
      </defs>
      <path d={`${d} L${w},${h} L0,${h} Z`} fill={`url(#g${id})`} />
      <path d={d} fill="none" stroke={c} strokeWidth={2} strokeLinecap="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** Four rising bars (the summary tiles' decoration). */
export function MiniBars({ tone }: { tone: Tone }) {
  const c = TONES[tone].line;
  return (
    <svg viewBox="0 0 44 36" className="h-9 w-11" aria-hidden>
      {[10, 18, 26, 34].map((hgt, i) => (
        <rect key={i} x={i * 11 + 2} y={36 - hgt} width={7} height={hgt} rx={2} fill={c} opacity={0.35 + i * 0.2} />
      ))}
    </svg>
  );
}

/** Online / offline / attention pill. */
export function StatusPill({ online, attention }: { online: boolean; attention?: boolean }) {
  if (!online) return <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full whitespace-nowrap bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-500"><span className="h-1.5 w-1.5 rounded-full bg-slate-400" />Offline</span>;
  if (attention) return <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full whitespace-nowrap bg-red-50 px-2.5 py-0.5 text-xs font-medium text-red-600"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-red-500" />Attention</span>;
  return <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full whitespace-nowrap bg-green-50 px-2.5 py-0.5 text-xs font-medium text-green-700"><span className="h-1.5 w-1.5 rounded-full bg-green-500" />Online</span>;
}

/** The cPanel mark in its orange, or a server icon. */
export function PanelMark({ panel, big }: { panel: string; big?: boolean }) {
  if (panel === 'cpanel') return <span className={`${big ? 'text-[34px]' : 'text-[26px]'} leading-none font-black tracking-tighter text-orange-500 italic`}>cP</span>;
  return null;
}
