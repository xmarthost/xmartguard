import { useEffect, useRef, useState } from 'react';
import { ChevronDown, Download } from 'lucide-react';

export const RANGES: { l: string; s: number }[] = [
  { l: 'Last 1 hour', s: 3600 },
  { l: 'Last 12 hours', s: 12 * 3600 },
  { l: 'Last 24 hours', s: 86400 },
  { l: 'Last 7 days', s: 7 * 86400 },
  { l: 'Last 30 days', s: 30 * 86400 },
  { l: 'Everything', s: 0 },
];

/** Saves text as a file in the browser. */
export function saveFile(name: string, text: string, type = 'text/csv') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Fetches every row of a list since a time, newest first, page by page with
 * a before-id cursor (new rows arriving meanwhile cause no repeats).
 */
export async function fetchAll<T extends { id: number }>(
  page: (since: number, beforeId: number) => Promise<T[]>,
  seconds: number,
  onProgress: (n: number) => void,
): Promise<T[]> {
  const since = seconds ? Math.floor(Date.now() / 1000) - seconds : 0;
  const all: T[] = [];
  let before = 0;
  for (;;) {
    const rows = await page(since, before);
    if (!rows.length) break;
    all.push(...rows);
    onProgress(all.length);
    before = rows[rows.length - 1].id;
  }
  return all;
}

/** A download button with a menu of time ranges. */
export function DownloadRange({ onPick, busyText, disabled }: { onPick: (seconds: number, label: string) => void; busyText?: string; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);
  return (
    <div className="relative" ref={ref}>
      <button className="btn-outline" title="Download logs (CSV)" disabled={disabled || !!busyText} onClick={() => setOpen(!open)}>
        <Download className="h-4 w-4" />
        {busyText ? <span className="text-xs">{busyText}</span> : <ChevronDown className="h-3.5 w-3.5" />}
      </button>
      {open && (
        <div className="absolute right-0 z-30 mt-1 w-44 overflow-hidden rounded-lg border border-slate-200 bg-white py-1 text-sm shadow-lg">
          <div className="px-3 py-1.5 text-xs text-slate-400">Download logs of</div>
          {RANGES.map((r) => (
            <button
              key={r.l}
              className="block w-full px-3 py-1.5 text-left hover:bg-slate-50"
              onClick={() => {
                setOpen(false);
                onPick(r.s, r.l);
              }}
            >
              {r.l}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
