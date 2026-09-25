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
      try {
        sha256[arch] = fs.readFileSync(path.join(downloadsDir, `xmartguard-agent-linux-${arch}.sha256`), 'utf8').split(/\s+/)[0];
      } catch {
        /* arch not built */
      }
    }
    if (version) rel = { version, sha256 };
  } catch {
    rel = null;
  }
  cached = { at: Date.now(), dir: downloadsDir, rel };
  return rel;
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
