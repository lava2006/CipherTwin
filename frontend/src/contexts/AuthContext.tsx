import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "@/lib/api";
import type { UserOut } from "@/lib/types";

interface AuthState {
  user: UserOut | null;
  token: string | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<UserOut>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserOut | null>(null);
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("ct_token"));
  const [loading, setLoading] = useState<boolean>(!!localStorage.getItem("ct_token"));

  useEffect(() => {
    let cancelled = false;
    async function bootstrap() {
      if (!localStorage.getItem("ct_token")) {
        setLoading(false);
        return;
      }
      try {
        const res = await api.get<UserOut>("/auth/me");
        if (!cancelled) setUser(res.data);
      } catch {
        localStorage.removeItem("ct_token");
        setToken(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    bootstrap();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const res = await api.post<{ access_token: string; user: UserOut }>("/auth/login", {
      username,
      password,
    });
    localStorage.setItem("ct_token", res.data.access_token);
    setToken(res.data.access_token);
    setUser(res.data.user);
    return res.data.user;
  }, []);

  const logout = useCallback(() => {
    try {
      api.post("/auth/logout");
    } catch {
      /* ignore */
    }
    localStorage.removeItem("ct_token");
    setToken(null);
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, token, loading, login, logout }),
    [user, token, loading, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
