// Writes Brotli and gzip copies of the built files next to them; the portal
// serves those to browsers that accept them (no compression per request).
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';

const root = new URL('../dist/', import.meta.url).pathname;
let files = 0;
let before = 0;
let after = 0;
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      walk(p);
      continue;
    }
    if (!/\.(?:js|css|html|svg|json|txt)$/.test(name)) continue;
    const raw = readFileSync(p);
    if (raw.length < 1024) continue;
    const br = brotliCompressSync(raw, { params: { [constants.BROTLI_PARAM_QUALITY]: 11, [constants.BROTLI_PARAM_SIZE_HINT]: raw.length } });
    writeFileSync(p + '.br', br);
    writeFileSync(p + '.gz', gzipSync(raw, { level: 9 }));
    files++;
    before += raw.length;
    after += br.length;
  }
};
walk(root);
console.log(`compressed ${files} files: ${(before / 1024).toFixed(0)} KB -> ${(after / 1024).toFixed(0)} KB (brotli)`);
