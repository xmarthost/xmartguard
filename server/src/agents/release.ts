import dns from 'node:dns/promises';
import type { Pool } from '../db.js';
import fs from 'node:fs';
import path from 'node:path';

export interface Release {
  version: string;
  sha256: Record<string, string>; // arch -> sha256
}

let cached: { at: number; dir: string; rel: Release | null } | null = null;

/** Reads the agent release bundled with this portal (dist/downloads). */
export function currentRelease(downloadsDir: string): Release | null {
  if (cached && cached.dir === downloadsDir && Date.now() - cached.at < 60_000) return cached.rel;
  let rel: Release | null = null;
  try {
    const version = fs.readFileSync(path.join(downloadsDir, 'VERSION'), 'utf8').trim();
    const sha256: Record<string, string> = {};
    for (const arch of ['amd64', 'arm64']) {
      for (const name of [`xpguard-agent-linux-${arch}.sha256`, `xmartguard-agent-linux-${arch}.sha256`]) {
        try {
          sha256[arch] = fs.readFileSync(path.join(downloadsDir, name), 'utf8').split(/\s+/)[0];
          break;
        } catch {
          /* arch not built under this name */
        }
      }
    }
    if (version) rel = { version, sha256 };
  } catch {
    rel = null;
  }
  cached = { at: Date.now(), dir: downloadsDir, rel };
  return rel;
}

/**
 * The agent.update parameters for a server of this architecture (one place
 * for every caller: audit A10 F9). Servers that never said are amd64.
 */
export function updateParams(rel: Release, arch: unknown): { sha256: string; version: string } {
  const a = typeof arch === 'string' && arch ? arch : 'amd64';
  // The version lets agents from 0.24.57 take the binary from the GitHub
  // release (checked against this checksum and the release signature)
  // instead of through the portal's web server.
  return { sha256: rel.sha256[a] ?? '', version: rel.version };
}

/** Compares dotted versions numerically; non-numeric parts sort lowest. */
export function versionLess(a: string, b: string): boolean {
  const pa = a.split(/[.-]/).map((x) => Number.parseInt(x, 10));
  const pb = b.split(/[.-]/).map((x) => Number.parseInt(x, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = Number.isFinite(pa[i]) ? pa[i] : -1;
    const y = Number.isFinite(pb[i]) ? pb[i] : -1;
    if (x !== y) return x < y;
  }
  return false;
}

let hostCache: { at: number; ips: Set<string> } | null = null;

/**
 * The servers that host the portal itself (their address is one the
 * portal's public name points to). Their agent's update restarts the web
 * server in front of the portal (it reloads the WAF), which cut the other
 * agents' update downloads and connections (2026-11-13): they are updated
 * last.
 */
export async function portalHostIds(pool: Pool, publicUrl: string): Promise<Set<string>> {
  if (!hostCache || Date.now() - hostCache.at > 10 * 60_000) {
    const ips = new Set<string>();
    try {
      for (const a of await dns.lookup(new URL(publicUrl).hostname, { all: true })) ips.add(a.address);
    } catch {
      // no answer: nobody is held back
    }
    hostCache = { at: Date.now(), ips };
  }
  if (!hostCache.ips.size) return new Set();
  const { rows } = await pool.query("SELECT id FROM servers WHERE status = 'active' AND primary_ip = ANY($1::text[])", [[...hostCache.ips]]);
  return new Set(rows.map((r) => String(r.id)));
}
