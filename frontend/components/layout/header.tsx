"use client";

import { Activity } from "lucide-react";

interface HeaderProps {
  title?: string;
  status?: string;
}

export function Header({ title = "CyberHunter", status }: HeaderProps) {
  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-border bg-background/80 backdrop-blur-md px-6">
      <h1 className="text-sm font-semibold tracking-wide uppercase text-muted-foreground">
        {title}
      </h1>
      {status && (
        <div className="flex items-center gap-2 text-xs">
          <Activity className="h-3.5 w-3.5 text-primary animate-pulse" />
          <span className="text-muted-foreground">{status}</span>
        </div>
      )}
    </header>
  );
}
