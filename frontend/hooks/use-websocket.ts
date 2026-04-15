"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { AgentEvent } from "@/lib/types";

type ConnectionState = "connecting" | "connected" | "disconnected" | "error";

export function useWebSocket(url: string | null) {
  const wsRef = useRef<WebSocket | null>(null);
  const [state, setState] = useState<ConnectionState>("disconnected");
  const [events, setEvents] = useState<AgentEvent[]>([]);

  useEffect(() => {
    if (!url) return;
    setState("connecting");

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setState("connected");

    ws.onmessage = (e) => {
      try {
        const event: AgentEvent = JSON.parse(e.data);
        setEvents((prev) => [...prev, event]);
      } catch {
        /* ignore malformed */
      }
    };

    ws.onerror = () => setState("error");
    ws.onclose = () => setState("disconnected");

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [url]);

  const send = useCallback((data: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { state, events, send, clearEvents };
}
