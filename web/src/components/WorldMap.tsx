import { useMemo, useState } from 'react';
import { geoCentroid, geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import type { Feature, FeatureCollection, Geometry } from 'geojson';
import type { GeometryCollection, Topology } from 'topojson-specification';
import countries from 'i18n-iso-countries';
import world from 'world-atlas/countries-110m.json';

const regionNames = (() => {
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' });
  } catch {
    return null;
  }
})();

export function countryName(cc: string): string {
  if (!/^[A-Z]{2}$/.test(cc)) return 'Unknown';
  try {
    return regionNames?.of(cc) ?? cc;
  } catch {
    return cc;
  }
}

/** Emoji flag for an ISO alpha-2 code. */
export function flag(cc: string): string {
  if (!/^[A-Z]{2}$/.test(cc)) return '🏳️';
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

type CountryFeature = Feature<Geometry, { name: string }> & { cc: string };

const W = 960;
const H = 480;

function useFeatures() {
  return useMemo(() => {
    const topo = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
    const fc = feature(topo, topo.objects.countries) as FeatureCollection<Geometry, { name: string }>;
    const projection = geoNaturalEarth1().fitSize([W, H], fc);
    const path = geoPath(projection);
    const feats: CountryFeature[] = fc.features
      .filter((f) => f.properties.name !== 'Antarctica')
      .map((f) => ({ ...f, cc: countries.numericToAlpha2(String(f.id ?? '')) ?? '' }));
    return { feats, path, projection };
  }, []);
}

/**
 * A dotted world map with threat markers (the Modern style's "Global Threat
 * Overview"): countries are drawn as dots, the busiest attack origins get a
 * coloured marker by tier.
 */
export function ThreatDotMap({ values }: { values: Record<string, number> }) {
  const { feats, path, projection } = useFeatures();
  const [hover, setHover] = useState<{ cc: string; x: number; y: number } | null>(null);
  const max = Math.max(1, ...Object.values(values));
  const markers = useMemo(
    () =>
      Object.entries(values)
        .filter(([, n]) => n > 0)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 24)
        .map(([cc, n]) => {
          const f = feats.find((x) => x.cc === cc);
          const p = f ? projection(geoCentroid(f)) : null;
          return p ? { cc, n, p, tier: threatTier(n, max) } : null;
        })
        .filter((m): m is { cc: string; n: number; p: [number, number]; tier: 'high' | 'medium' | 'low' } => !!m)
        .reverse(),
    [values, feats, projection, max],
  );
  const col = { high: '#ef4444', medium: '#f59e0b', low: '#22c55e' };
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Attack origins by country">
        <defs>
          <pattern id="xg-dots" width="7" height="7" patternUnits="userSpaceOnUse">
            <circle cx="3.5" cy="3.5" r="1.7" className="xg-map-dot" fill="#b9cfe8" />
          </pattern>
        </defs>
        {feats.map((f, i) => (
          <path key={i} d={path(f) ?? ''} fill="url(#xg-dots)" />
        ))}
        {markers.map((m) => (
          <g
            key={m.cc}
            transform={`translate(${m.p[0]},${m.p[1]})`}
            onMouseMove={(e) => {
              const box = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
              setHover({ cc: m.cc, x: e.clientX - box.left, y: e.clientY - box.top });
            }}
            onMouseLeave={() => setHover(null)}
            className="cursor-pointer"
          >
            <circle r={m.tier === 'high' ? 26 : m.tier === 'medium' ? 16 : 10} fill={col[m.tier]} opacity={0.14} />
            <circle r={m.tier === 'high' ? 14 : m.tier === 'medium' ? 9 : 6} fill={col[m.tier]} opacity={0.22} />
            <circle r={m.tier === 'high' ? 7 : m.tier === 'medium' ? 5 : 4} fill={col[m.tier]} />
          </g>
        ))}
      </svg>
      {hover && (
        <div className="pointer-events-none absolute z-10 rounded-md bg-slate-900 px-3 py-2 text-xs text-white shadow-lg" style={{ left: hover.x + 12, top: hover.y + 12 }}>
          <div className="font-semibold">
            {flag(hover.cc)} {countryName(hover.cc)}
          </div>
          <div>{(values[hover.cc] ?? 0).toLocaleString()} blocked (30 days)</div>
        </div>
      )}
    </div>
  );
}

/** A country's threat tier from its share of the busiest one. */
export function threatTier(n: number, max: number): 'high' | 'medium' | 'low' {
  if (n >= max * 0.4) return 'high';
  if (n >= max * 0.08) return 'medium';
  return 'low';
}

/**
 * Choropleth of blocked traffic per country, with pulsing markers for the
 * countries that were active in the last minute.
 */
export function WorldMap({ values, live = [] }: { values: Record<string, number>; live?: string[] }) {
  const { feats, path, projection } = useFeatures();
  const [hover, setHover] = useState<{ cc: string; name: string; x: number; y: number } | null>(null);
  const max = Math.max(1, ...Object.values(values));
  const color = (n: number) => {
    if (!n) return '#e2e8f0';
    const t = Math.log(1 + n) / Math.log(1 + max); // log scale: a few busy countries don't wash out the rest
    const a = 0.2 + 0.8 * t;
    return `rgba(220, 38, 38, ${a.toFixed(3)})`;
  };
  const markers = useMemo(
    () =>
      [...new Set(live)]
        .map((cc) => feats.find((f) => f.cc === cc))
        .filter((f): f is CountryFeature => !!f)
        .map((f) => ({ cc: f.cc, p: projection(geoCentroid(f)) }))
        .filter((m): m is { cc: string; p: [number, number] } => !!m.p),
    [live, feats, projection],
  );

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Attack origins by country">
        <rect width={W} height={H} fill="#f8fafc" rx={12} />
        {feats.map((f, i) => (
          <path
            key={i}
            d={path(f) ?? ''}
            fill={color(values[f.cc] ?? 0)}
            stroke="#fff"
            strokeWidth={0.5}
            onMouseMove={(e) => {
              const box = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
              setHover({ cc: f.cc, name: f.properties.name, x: e.clientX - box.left, y: e.clientY - box.top });
            }}
            onMouseLeave={() => setHover(null)}
            className="cursor-pointer transition-opacity hover:opacity-80"
          />
        ))}
        {markers.map((m) => (
          <g key={m.cc} transform={`translate(${m.p[0]},${m.p[1]})`}>
            <circle r={4} fill="#dc2626" />
            <circle r={4} fill="none" stroke="#dc2626" strokeWidth={2}>
              <animate attributeName="r" from="4" to="22" dur="1.6s" repeatCount="indefinite" />
              <animate attributeName="opacity" from="0.9" to="0" dur="1.6s" repeatCount="indefinite" />
            </circle>
          </g>
        ))}
      </svg>
      {hover && (
        <div
          className="pointer-events-none absolute z-10 rounded-md bg-navy-900 px-3 py-2 text-xs text-white shadow-lg"
          style={{ left: hover.x + 12, top: hover.y + 12 }}
        >
          <div className="font-semibold">
            {flag(hover.cc)} {hover.name}
          </div>
          <div>{(values[hover.cc] ?? 0).toLocaleString()} blocked packets (30 days)</div>
        </div>
      )}
      <div className="mt-2 flex items-center gap-2 text-xs text-slate-500">
        <span>fewer</span>
        <span className="h-2 w-32 rounded" style={{ background: 'linear-gradient(to right, rgba(220,38,38,.2), rgba(220,38,38,1))' }} />
        <span>more attacks</span>
      </div>
    </div>
  );
}
