export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text };
  }
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/api/auth/')) window.dispatchEvent(new Event('xg:unauthorized'));
    throw new ApiError(res.status, data?.error || res.statusText);
  }
  return data as T;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'owner' | 'admin' | 'operator' | 'viewer';
}

export interface Process {
  pid: number;
  name: string;
  user: string;
  cpu_percent: number;
  mem_bytes: number;
  run_seconds: number;
}

export interface Metrics {
  ts: number;
  cpu_percent: number;
  load1: number;
  load5: number;
  load15: number;
  mem_total: number;
  mem_used: number;
  swap_total: number;
  swap_used: number;
  disk_total: number;
  disk_used: number;
  connections: number;
  uptime_seconds: number;
  top_processes: Process[];
}

export interface Inventory {
  hostname: string;
  os_name: string;
  os_version: string;
  kernel: string;
  arch: string;
  cpu_model: string;
  cpu_cores: number;
  mem_total_bytes: number;
  control_panel: string;
  web_server: string;
  primary_ip: string;
  ips: string[];
  virtualization?: string;
}

export interface Server {
  id: string;
  hostname: string;
  primary_ip: string;
  os_name: string;
  control_panel: string;
  web_server: string;
  agent_version: string;
  tags: string[];
  online: boolean;
  last_seen_at: string | null;
  created_at: string;
  inventory: Inventory;
  last_metrics: Metrics | null;
}

export interface MetricPoint {
  t: number;
  cpu: number;
  load1: number;
  load5: number;
  load15: number;
  mem_pct: number;
  disk_pct: number;
  connections: number;
}
