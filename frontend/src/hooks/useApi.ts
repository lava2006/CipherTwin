import { useEffect, useState } from "react";
import { api } from "@/lib/api";

export function useApi<T>(url: string, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function run() {
      try {
        setLoading(true);
        const res = await api.get<T>(url);
        if (active) setData(res.data);
      } catch (e: any) {
        if (active) setError(e?.message ?? "Request failed");
      } finally {
        if (active) setLoading(false);
      }
    }
    run();
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, ...deps]);

  return { data, loading, error, refresh: () => setLoading(true) };
}
