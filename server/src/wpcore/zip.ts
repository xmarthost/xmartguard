import zlib from 'node:zlib';

export interface ZipEntry {
  name: string;
  size: number;
  data: () => Buffer;
}

/**
 * Minimal ZIP reader (stored and deflated entries, no ZIP64) for the
 * WordPress release archives. It reads the central directory, so it works on
 * any conforming archive regardless of local-header data descriptors.
 */
export function readZip(buf: Buffer): ZipEntry[] {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip archive');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const out: ZipEntry[] = [];
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('corrupt zip directory');
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28);
    const xlen = buf.readUInt16LE(p + 30);
    const clen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nlen);
    p += 46 + nlen + xlen + clen;
    out.push({
      name,
      size: usize,
      data: () => {
        if (buf.readUInt32LE(local) !== 0x04034b50) throw new Error('corrupt zip entry');
        const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
        const raw = buf.subarray(start, start + csize);
        if (method === 0) return Buffer.from(raw);
        if (method === 8) return zlib.inflateRawSync(raw, { maxOutputLength: Math.max(usize, 1) + 1024 });
        throw new Error(`unsupported zip method ${method}`);
      },
    });
  }
  return out;
}
