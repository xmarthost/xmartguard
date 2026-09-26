import { useEffect, useState } from 'react';
import { api } from '../api';

const cache = new Map<string, string>();

/** Country codes for addresses, looked up in batches through the portal's GeoIP database. */
export function useCountries(ips: string[]): Record<string, string> {
  const key = ips.join(',');
  const [, bump] = useState(0);
  useEffect(() => {
    const missing = Array.from(new Set(ips.filter((ip) => ip && !cache.has(ip)))).slice(0, 500);
    if (!missing.length) return;
    let alive = true;
    api<{ countries: Record<string, string> }>('POST', '/api/geo/lookup', { ips: missing })
      .then((r) => {
        for (const ip of missing) cache.set(ip, r.countries[ip] ?? '');
        if (alive) bump((n) => n + 1);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  const out: Record<string, string> = {};
  for (const ip of ips) out[ip] = cache.get(ip) ?? '';
  return out;
}

/** Saves rows as a CSV download. */
export function downloadCSV(name: string, head: string[], rows: unknown[][]) {
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const text = [head.map(esc).join(','), ...rows.map((r) => r.map(esc).join(','))].join('\n');
  const url = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
