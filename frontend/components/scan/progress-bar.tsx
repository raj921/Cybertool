"use client";

import type { AgentEvent } from "@/lib/types";

interface ProgressBarProps {
  events: AgentEvent[];
  status: string;
}

export function ProgressBar({ events, status }: ProgressBarProps) {
  const toolCalls = events.filter((e) => e.type === "tool_start").length;
  const findings = events.filter(
    (e) => e.type === "finding_raw" || e.type === "finding"
  ).length;

  const isRunning = status === "running" || status === "connected";
  const isComplete = events.some(
    (e) => e.type === "status" && e.status === "completed"
  );

  return (
    <div className="flex items-center gap-6 border-b border-border px-6 py-2 text-xs text-muted-foreground bg-card/50">
      <div className="flex items-center gap-1.5">
        <div
          className={`h-2 w-2 rounded-full ${
            isComplete
              ? "bg-primary"
              : isRunning
                ? "bg-primary animate-pulse"
                : "bg-muted-foreground"
          }`}
        />
        <span className="font-medium">
          {isComplete ? "Complete" : isRunning ? "Hunting..." : "Idle"}
        </span>
      </div>
      <span>Tools: {toolCalls}</span>
      <span>Findings: {findings}</span>
    </div>
  );
}
