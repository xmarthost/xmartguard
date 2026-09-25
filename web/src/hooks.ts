import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api';

/** Fetches a GET endpoint, optionally polling every `intervalMs`. */
export function useApi<T>(path: string | null, intervalMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const alive = useRef(true);

  const load = useCallback(async () => {
    if (!path) return;
    try {
      const d = await api<T>('GET', path);
      if (alive.current) {
        setData(d);
        setError(null);
      }
    } catch (e: any) {
      if (alive.current) setError(e.message);
    } finally {
      if (alive.current) setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    alive.current = true;
    setLoading(true);
    load();
    let t: ReturnType<typeof setInterval> | undefined;
    if (intervalMs) t = setInterval(load, intervalMs);
    return () => {
      alive.current = false;
      if (t) clearInterval(t);
    };
  }, [load, intervalMs]);

  return { data, error, loading, reload: load };
}
