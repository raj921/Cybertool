"use client";

import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Download, FileText, Code } from "lucide-react";

interface ReportViewerProps {
  markdown: string;
  onDownload?: (format: "md" | "json" | "html") => void;
}

export function ReportViewer({ markdown, onDownload }: ReportViewerProps) {
  if (!markdown) {
    return (
      <Card className="p-8 text-center text-muted-foreground border-border">
        <FileText className="h-8 w-8 mx-auto mb-3 opacity-50" />
        <p className="text-sm">Report will appear here after the scan completes.</p>
      </Card>
    );
  }

  const lines = markdown.split("\n");

  return (
    <Card className="border-border overflow-hidden">
      <div className="flex items-center justify-between border-b border-border px-4 py-2">
        <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
          Report
        </h3>
        <div className="flex gap-1.5">
          {(["md", "json", "html"] as const).map((fmt) => (
            <Button
              key={fmt}
              variant="outline"
              size="sm"
              className="h-7 text-xs cursor-pointer"
              onClick={() => onDownload?.(fmt)}
            >
              <Download className="h-3 w-3 mr-1" />
              {fmt.toUpperCase()}
            </Button>
          ))}
        </div>
      </div>
      <ScrollArea className="h-[600px]">
        <pre className="p-4 text-sm font-mono text-foreground/90 whitespace-pre-wrap leading-relaxed">
          {lines.map((line, i) => {
            if (line.startsWith("# ")) {
              return (
                <div key={i} className="text-xl font-bold text-primary mt-4 mb-2">
                  {line.replace("# ", "")}
                </div>
              );
            }
            if (line.startsWith("## ")) {
              return (
                <div key={i} className="text-base font-bold text-foreground mt-6 mb-1 border-b border-border pb-1">
                  {line.replace("## ", "")}
                </div>
              );
            }
            if (line.startsWith("### ")) {
              return (
                <div key={i} className="text-sm font-semibold text-muted-foreground mt-3 mb-1">
                  {line.replace("### ", "")}
                </div>
              );
            }
            if (line.includes("[CRITICAL]")) {
              return <div key={i} className="text-red-400">{line}</div>;
            }
            if (line.includes("[HIGH]")) {
              return <div key={i} className="text-orange-400">{line}</div>;
            }
            if (line.includes("[MEDIUM]")) {
              return <div key={i} className="text-yellow-400">{line}</div>;
            }
            if (line === "---") {
              return <hr key={i} className="border-border my-3" />;
            }
            if (line.startsWith("```")) {
              return null;
            }
            return <div key={i}>{line}</div>;
          })}
        </pre>
      </ScrollArea>
    </Card>
  );
}
