"use client";

import { useEffect, useRef } from "react";
import {
  Brain,
  Terminal,
  AlertTriangle,
  Link2,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { AgentEvent } from "@/lib/types";

const EVENT_CONFIG: Record<
  string,
  { icon: React.ElementType; color: string; label: string }
> = {
  thinking: { icon: Brain, color: "text-blue-400", label: "THINK" },
  tool_start: { icon: Terminal, color: "text-zinc-400", label: "TOOL" },
  tool_result: { icon: CheckCircle2, color: "text-zinc-500", label: "RESULT" },
  finding_raw: { icon: AlertTriangle, color: "text-red-400", label: "FINDING" },
  finding: { icon: AlertTriangle, color: "text-red-400", label: "FINDING" },
  chain: { icon: Link2, color: "text-purple-400", label: "CHAIN" },
  status: { icon: CheckCircle2, color: "text-primary", label: "STATUS" },
  error: { icon: XCircle, color: "text-destructive", label: "ERROR" },
};

function getEventText(event: AgentEvent): string {
  if (event.text) return event.text;
  if (event.type === "tool_start") {
    return `Running: ${event.tool}(${JSON.stringify(event.args || {}).slice(0, 120)})`;
  }
  if (event.type === "tool_result") {
    return `${event.tool}: ${event.result_preview || "done"}`;
  }
  if (event.type === "status") {
    return event.status === "completed"
      ? "Scan complete."
      : `Status: ${event.status}`;
  }
  return JSON.stringify(event.data || event);
}

interface AIThinkingFeedProps {
  events: AgentEvent[];
}

export function AIThinkingFeed({ events }: AIThinkingFeedProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  return (
    <ScrollArea className="h-full">
      <div className="space-y-1 p-4 font-mono text-sm">
        {events.length === 0 && (
          <p className="text-muted-foreground text-center py-16">
            Waiting for agent to start...
          </p>
        )}
        {events.map((event, i) => {
          const cfg = EVENT_CONFIG[event.type] || EVENT_CONFIG.status;
          const Icon = cfg.icon;
          const text = getEventText(event);

          return (
            <div key={i} className="flex gap-2 py-1 group">
              <Icon className={`h-4 w-4 mt-0.5 shrink-0 ${cfg.color}`} />
              <div className="min-w-0">
                <span className={`text-xs font-bold ${cfg.color} mr-1.5`}>
                  [{cfg.label}]
                </span>
                <span className="text-foreground/90 break-words whitespace-pre-wrap">
                  {text}
                </span>
              </div>
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>
    </ScrollArea>
  );
}
