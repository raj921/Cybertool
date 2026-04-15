"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { listScans } from "@/lib/api";
import type { ScanResponse } from "@/lib/types";
import { Activity, Clock } from "lucide-react";

export default function ScansPage() {
  const [scans, setScans] = useState<ScanResponse[]>([]);

  useEffect(() => {
    listScans().then(setScans).catch(() => {});
  }, []);

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 pl-56">
        <Header title="Scan History" />
        <div className="p-6 max-w-4xl space-y-2">
          {scans.length === 0 && (
            <p className="text-sm text-muted-foreground py-12 text-center">
              No scans yet.
            </p>
          )}
          {scans.map((scan) => (
            <Link key={scan.id} href={`/dashboard/${scan.id}`}>
              <Card className="p-4 border-border hover:bg-accent/50 transition-colors cursor-pointer">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Activity className="h-4 w-4 text-primary" />
                    <div>
                      <p className="text-sm font-semibold font-mono">{scan.target}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <Badge variant="outline" className="text-[10px]">{scan.status}</Badge>
                        <Badge variant="outline" className="text-[10px]">{scan.profile}</Badge>
                        <span className="text-xs text-muted-foreground flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {new Date(scan.created_at).toLocaleString()}
                        </span>
                      </div>
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">{scan.findings_count} findings</span>
                </div>
              </Card>
            </Link>
          ))}
        </div>
      </main>
    </div>
  );
}
