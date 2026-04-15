"use client";

import { useRouter } from "next/navigation";
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { TargetInput } from "@/components/scan/target-input";
import { useScan } from "@/hooks/use-scan";
import { Shield, Zap, Eye, Brain } from "lucide-react";
import type { ScanConfig } from "@/lib/types";

const FEATURES = [
  {
    icon: Brain,
    title: "AI-Driven",
    desc: "Claude-powered agent thinks like a pro hunter",
  },
  {
    icon: Zap,
    title: "Parallel Recon",
    desc: "All tools run simultaneously for speed",
  },
  {
    icon: Eye,
    title: "Zero False Positives",
    desc: "5-layer verification eliminates noise",
  },
  {
    icon: Shield,
    title: "Full Coverage",
    desc: "XSS, SQLi, SSRF, IDOR, OAuth, JWT + 30 more",
  },
];

export default function HomePage() {
  const router = useRouter();
  const { startScan, loading } = useScan();

  const handleStart = async (config: ScanConfig) => {
    const scan = await startScan(config);
    if (scan) {
      router.push(`/dashboard/${scan.id}`);
    }
  };

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 pl-56">
        <Header title="New Scan" />
        <div className="mx-auto max-w-2xl px-6 py-16">
          <div className="text-center mb-10">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-primary/10 mb-4">
              <Shield className="h-8 w-8 text-primary" />
            </div>
            <h2 className="text-3xl font-bold tracking-tight">CyberHunter</h2>
            <p className="text-muted-foreground mt-2 text-base">
              Autonomous AI bug bounty hunter. Enter a target and watch it hunt.
            </p>
          </div>

          <TargetInput onStart={handleStart} loading={loading} />

          <div className="mt-12 grid grid-cols-2 gap-4">
            {FEATURES.map(({ icon: Icon, title, desc }) => (
              <div
                key={title}
                className="rounded-lg border border-border bg-card/50 p-4"
              >
                <Icon className="h-5 w-5 text-primary mb-2" />
                <h3 className="text-sm font-semibold">{title}</h3>
                <p className="text-xs text-muted-foreground mt-1">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
