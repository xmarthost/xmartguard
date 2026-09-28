import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { applyAppearance, type Appearance } from './theme';
import { api, type User } from './api';

interface AuthState {
  user: User | null;
  loading: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthState>(null!);

const RANK = { viewer: 0, operator: 1, admin: 2, owner: 3 } as const;

export function can(user: User | null, min: keyof typeof RANK): boolean {
  return !!user && RANK[user.role] >= RANK[min];
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const r = await api<{ user: User }>('GET', '/api/auth/me');
      setUser(r.user);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    await api('POST', '/api/auth/logout').catch(() => {});
    setUser(null);
  }, []);

  useEffect(() => {
    refresh();
    const onUnauth = () => setUser(null);
    window.addEventListener('xg:unauthorized', onUnauth);
    return () => window.removeEventListener('xg:unauthorized', onUnauth);
  }, [refresh]);

  // The signed-in account's theme applies as soon as the user is known
  // (the page may have loaded on the login screen or with an old session).
  const signedIn = user?.id;
  useEffect(() => {
    if (!signedIn) return;
    api<{ appearance: Appearance }>('GET', '/api/appearance')
      .then((r) => applyAppearance(r.appearance))
      .catch(() => {});
  }, [signedIn]);

  return <Ctx.Provider value={{ user, loading, refresh, logout }}>{children}</Ctx.Provider>;
}

export const useAuth = () => useContext(Ctx);
