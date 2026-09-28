import { useEffect, useState } from "react";
import { api } from "@/lib/api";

export function usePolling<T>(url: string, intervalMs = 5000): { data: T | null; loading: boolean } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function tick() {
      try {
        const res = await api.get<T>(url);
        if (active) {
          setData(res.data);
          setLoading(false);
        }
      } catch {
        if (active) setLoading(false);
      }
    }
    tick();
    const id = setInterval(tick, intervalMs);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [url, intervalMs]);

  return { data, loading };
}
