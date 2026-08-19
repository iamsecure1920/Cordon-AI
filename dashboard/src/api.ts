import { useEffect, useRef, useState } from "react";
import type { DashboardState } from "./types";

export async function fetchState(ws?: string): Promise<DashboardState> {
  const q = ws ? `?ws=${encodeURIComponent(ws)}` : "";
  const res = await fetch(`/api/state${q}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`state fetch failed: ${res.status}`);
  return res.json() as Promise<DashboardState>;
}

export interface LiveState {
  state: DashboardState | null;
  error: string | null;
  connected: boolean;
  refetch: () => void;
}

/**
 * Poll /api/state every `intervalMs` (default 2000). Returns the latest blob
 * plus a `connected` flag that goes stale when a poll fails — the topbar's
 * live dot keys off it.
 */
export function useLiveState(intervalMs = 2000, ws?: string): LiveState {
  const [state, setState] = useState<DashboardState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [tick, setTick] = useState(0);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      fetchState(ws)
        .then((s) => {
          if (cancelled) return;
          setState(s);
          setError(null);
          setConnected(true);
        })
        .catch((e: unknown) => {
          if (cancelled) return;
          setError(e instanceof Error ? e.message : String(e));
          setConnected(false);
        });
    load();
    if (timer.current) window.clearInterval(timer.current);
    timer.current = window.setInterval(load, intervalMs);
    return () => {
      cancelled = true;
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [intervalMs, ws, tick]);

  return {
    state,
    error,
    connected,
    refetch: () => setTick((t) => t + 1),
  };
}
