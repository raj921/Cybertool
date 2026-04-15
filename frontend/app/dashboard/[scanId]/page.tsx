"use client";

import { use, useEffect, useMemo, useState } from "react";
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { AIThinkingFeed } from "@/components/scan/ai-thinking-feed";
import { FindingsPanel } from "@/components/scan/findings-panel";
import { ProgressBar } from "@/components/scan/progress-bar";
import { useWebSocket } from "@/hooks/use-websocket";
import { getScan, getWsUrl } from "@/lib/api";
import type { ScanResponse } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Square } from "lucide-react";

export default function ScanPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = use(params);
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [started, setStarted] = useState(false);

  const wsUrl = useMemo(() => getWsUrl(scanId), [scanId]);
  const { state, events, send } = useWebSocket(wsUrl);

  useEffect(() => {
    getScan(scanId).then(setScan).catch(() => {});
  }, [scanId]);

  useEffect(() => {
    if (state === "connected" && scan && !started) {
      send({
        action: "start",
        target: scan.target,
        scope_config: scan.scope_config,
        model_role: scan.model_role,
      });
      setStarted(true);
    }
  }, [state, scan, started, send]);

  const isComplete = events.some(
    (e) => e.type === "status" && e.status === "completed"
  );

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 pl-56 flex flex-col h-screen">
        <Header
          title={scan ? `Hunting: ${scan.target}` : "Loading..."}
          status={isComplete ? "Complete" : state === "connected" ? "Connected" : state}
        />
        <ProgressBar events={events} status={state} />

        <div className="flex flex-1 min-h-0">
          {/* AI Thinking Feed -- 2/3 width */}
          <div className="flex-1 border-r border-border overflow-hidden">
            <AIThinkingFeed events={events} />
          </div>

          {/* Findings Panel -- 1/3 width */}
          <div className="w-80 shrink-0 overflow-hidden">
            <FindingsPanel events={events} />
          </div>
        </div>

        {!isComplete && started && (
          <div className="border-t border-border px-6 py-2 flex justify-end bg-card/50">
            <Button
              variant="outline"
              size="sm"
              onClick={() => send({ action: "stop" })}
              className="cursor-pointer"
            >
              <Square className="h-3 w-3 mr-1.5" />
              Stop Scan
            </Button>
          </div>
        )}
      </main>
    </div>
  );
}
