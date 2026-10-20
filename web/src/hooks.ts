import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api';
import { requestGate } from './requestGate';

/** Fetches a GET endpoint, optionally polling every `intervalMs`. */
export function useApi<T>(path: string | null, intervalMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(!!path);
  // Another path (another server): drop what was shown, and any answer
  // still on the way for the old path.
  const gate = useRef(requestGate(path ?? '')).current;
  if (gate.use(path ?? '')) {
    setData(null);
    setError(null);
    setLoading(!!path);
  }

  const load = useCallback(async () => {
    if (!path) return;
    const ok = gate.begin(path);
    try {
      const d = await api<T>('GET', path);
      if (ok()) {
        setData(d);
        setError(null);
      }
    } catch (e: any) {
      if (ok()) setError(e.message);
    } finally {
      if (ok()) setLoading(false);
    }
  }, [path, gate]);

  useEffect(() => {
    if (!path) {
      setLoading(false);
      return;
    }
    setLoading(true);
    load();
    let t: ReturnType<typeof setInterval> | undefined;
    let busy = false;
    if (intervalMs)
      t = setInterval(async () => {
        if (busy || document.hidden) return;
        busy = true;
        try {
          await load();
        } finally {
          busy = false;
        }
      }, intervalMs);
    return () => {
      if (t) clearInterval(t);
    };
  }, [load, intervalMs, path]);

  return { data, error, loading, reload: load };
}
