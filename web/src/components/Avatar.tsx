import { useEffect, useState } from 'react';

const hashes = new Map<string, string>();

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The user's Gravatar (the photo set for their email at gravatar.com); the
 * first letter of the name while it loads or when the email has none.
 */
export function Avatar({ email, name, size = 36, className = '' }: { email: string; name?: string; size?: number; className?: string }) {
  const key = email.trim().toLowerCase();
  const [hash, setHash] = useState(() => hashes.get(key) ?? '');
  const [ok, setOk] = useState(false);
  useEffect(() => {
    setOk(false);
    if (hashes.has(key)) return setHash(hashes.get(key)!);
    if (!key || !crypto?.subtle) return setHash('');
    let live = true;
    sha256(key)
      .then((h) => {
        hashes.set(key, h);
        if (live) setHash(h);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [key]);
  const letter = (name || email)[0]?.toUpperCase() ?? '?';
  return (
    <span
      className={`relative inline-flex shrink-0 items-center justify-center overflow-hidden rounded-full bg-green-500 font-semibold text-white ${className}`}
      style={{ width: size, height: size }}
    >
      {!ok && letter}
      {hash && (
        <img
          src={`https://gravatar.com/avatar/${hash}?s=${size * 2}&d=404`}
          alt=""
          referrerPolicy="no-referrer"
          className={`absolute inset-0 h-full w-full object-cover ${ok ? '' : 'invisible'}`}
          onLoad={() => setOk(true)}
          onError={() => setOk(false)}
        />
      )}
    </span>
  );
}
