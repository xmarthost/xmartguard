export function bytes(n: number | undefined | null, digits = 1): string {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : digits)} ${units[i]}`;
}

export function pct(used: number | undefined, total: number | undefined): number {
  if (!used || !total) return 0;
  return Math.round((used / total) * 1000) / 10;
}

export function duration(seconds: number | undefined): string {
  if (!seconds) return '0s';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d}d ${h}h ${m}m`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return `${Math.floor(seconds)}s`;
}

export function ago(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

const PANELS: Record<string, string> = {
  cpanel: 'cPanel/WHM',
  directadmin: 'DirectAdmin',
  plesk: 'Plesk',
  cyberpanel: 'CyberPanel',
  cwp: 'CWP',
  webuzo: 'Webuzo',
  interworx: 'InterWorx',
  enhance: 'Enhance',
  webmin: 'Webmin',
  standalone: 'Standalone',
};

export function panelName(p: string | undefined): string {
  return (p && PANELS[p]) || p || 'Unknown';
}

/** Load status relative to core count, like the portal's Low/Medium/High label. */
export function loadLevel(load: number, cores: number): { label: string; cls: string } {
  const r = cores ? load / cores : load;
  if (r < 0.7) return { label: 'Low', cls: 'bg-green-50 border-green-500 text-green-700' };
  if (r < 1) return { label: 'Medium', cls: 'bg-amber-50 border-amber-500 text-amber-700' };
  return { label: 'High', cls: 'bg-red-50 border-red-500 text-red-700' };
}
