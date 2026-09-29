import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";

export function usePolling<T>(
  url: string,
  intervalMs = 5000,
): { data: T | null; loading: boolean; refetch: () => Promise<void> } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);

  const refetch = useCallback(async () => {
    try {
      const res = await api.get<T>(url);
      setData(res.data);
      setLoading(false);
    } catch {
      setLoading(false);
    }
  }, [url]);

  useEffect(() => {
    let active = true;
    refetch();
    const id = setInterval(() => {
      if (active) refetch();
    }, intervalMs);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [refetch, intervalMs]);

  return { data, loading, refetch };
}
