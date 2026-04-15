"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { listScans } from "@/lib/api";
import type { ScanResponse } from "@/lib/types";
import { Activity, ArrowRight, Clock } from "lucide-react";

export default function DashboardPage() {
  const [scans, setScans] = useState<ScanResponse[]>([]);

  useEffect(() => {
    listScans().then(setScans).catch(() => {});
  }, []);

  const statusColor: Record<string, string> = {
    running: "text-primary",
    completed: "text-green-400",
    pending: "text-yellow-400",
    failed: "text-destructive",
  };

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 pl-56">
        <Header title="Dashboard" />
        <div className="p-6 space-y-4 max-w-4xl">
          <div className="grid grid-cols-3 gap-4">
            <Card className="p-4 border-border">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Total Scans</p>
              <p className="text-2xl font-bold mt-1">{scans.length}</p>
            </Card>
            <Card className="p-4 border-border">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Running</p>
              <p className="text-2xl font-bold mt-1 text-primary">
                {scans.filter((s) => s.status === "running").length}
              </p>
            </Card>
            <Card className="p-4 border-border">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Total Findings</p>
              <p className="text-2xl font-bold mt-1">
                {scans.reduce((sum, s) => sum + s.findings_count, 0)}
              </p>
            </Card>
          </div>

          <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground pt-4">
            Recent Scans
          </h3>
          <div className="space-y-2">
            {scans.length === 0 && (
              <p className="text-sm text-muted-foreground py-8 text-center">
                No scans yet. Start one from the home page.
              </p>
            )}
            {scans.map((scan) => (
              <Link key={scan.id} href={`/dashboard/${scan.id}`}>
                <Card className="p-4 border-border hover:bg-accent/50 transition-colors cursor-pointer flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Activity className={`h-4 w-4 ${statusColor[scan.status] || "text-muted-foreground"}`} />
                    <div>
                      <p className="text-sm font-semibold font-mono">{scan.target}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <Badge variant="outline" className="text-[10px]">{scan.profile}</Badge>
                        <span className="text-xs text-muted-foreground flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {new Date(scan.created_at).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground">
                      {scan.findings_count} findings
                    </span>
                    <ArrowRight className="h-4 w-4 text-muted-foreground" />
                  </div>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
