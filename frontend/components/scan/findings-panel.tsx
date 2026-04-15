"use client";

import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ShieldAlert, ShieldCheck, Shield, Info } from "lucide-react";
import type { AgentEvent } from "@/lib/types";

const SEVERITY_CONFIG = {
  critical: { icon: ShieldAlert, bg: "bg-red-500/15", text: "text-red-400", badge: "border-red-500/50 text-red-400" },
  high: { icon: ShieldAlert, bg: "bg-orange-500/15", text: "text-orange-400", badge: "border-orange-500/50 text-orange-400" },
  medium: { icon: Shield, bg: "bg-yellow-500/15", text: "text-yellow-400", badge: "border-yellow-500/50 text-yellow-400" },
  low: { icon: ShieldCheck, bg: "bg-blue-500/15", text: "text-blue-400", badge: "border-blue-500/50 text-blue-400" },
  info: { icon: Info, bg: "bg-zinc-500/15", text: "text-zinc-400", badge: "border-zinc-500/50 text-zinc-400" },
} as const;

interface FindingsPanelProps {
  events: AgentEvent[];
}

function parseFinding(text: string): { title: string; severity: string; type: string } | null {
  const titleMatch = text.match(/Title:\s*(.+)/i);
  const severityMatch = text.match(/Severity:\s*(\w+)/i);
  const typeMatch = text.match(/Type:\s*(\w+)/i);
  if (!titleMatch) return null;
  return {
    title: titleMatch[1].trim(),
    severity: (severityMatch?.[1] || "medium").toLowerCase(),
    type: typeMatch?.[1] || "unknown",
  };
}

export function FindingsPanel({ events }: FindingsPanelProps) {
  const findingEvents = events.filter(
    (e) => e.type === "finding_raw" || e.type === "finding"
  );

  const parsed = findingEvents
    .map((e) => parseFinding(e.text || ""))
    .filter(Boolean) as { title: string; severity: string; type: string }[];

  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of parsed) {
    const sev = f.severity in counts ? f.severity : "medium";
    counts[sev]++;
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
          Findings
        </h2>
        <div className="mt-2 flex gap-2 flex-wrap">
          {Object.entries(counts).map(([sev, count]) => {
            if (count === 0) return null;
            const cfg = SEVERITY_CONFIG[sev as keyof typeof SEVERITY_CONFIG];
            return (
              <Badge key={sev} variant="outline" className={cfg.badge}>
                {sev.toUpperCase()} {count}
              </Badge>
            );
          })}
          {parsed.length === 0 && (
            <span className="text-xs text-muted-foreground">No findings yet</span>
          )}
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="space-y-2 p-3">
          {parsed.map((f, i) => {
            const sev = f.severity in SEVERITY_CONFIG ? f.severity as keyof typeof SEVERITY_CONFIG : "medium";
            const cfg = SEVERITY_CONFIG[sev];
            const Icon = cfg.icon;
            return (
              <Card key={i} className={`${cfg.bg} border-none p-3`}>
                <div className="flex items-start gap-2">
                  <Icon className={`h-4 w-4 mt-0.5 ${cfg.text}`} />
                  <div className="min-w-0">
                    <span className={`text-xs font-bold uppercase ${cfg.text}`}>
                      {f.severity}
                    </span>
                    <p className="text-sm text-foreground/90 mt-0.5 break-words">
                      {f.title}
                    </p>
                    <span className="text-xs text-muted-foreground">{f.type}</span>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      </ScrollArea>
    </div>
  );
}
