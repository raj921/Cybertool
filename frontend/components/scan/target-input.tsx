"use client";

import { useState } from "react";
import { Crosshair, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import type { ScanConfig } from "@/lib/types";

interface TargetInputProps {
  onStart: (config: ScanConfig) => void;
  loading?: boolean;
}

export function TargetInput({ onStart, loading }: TargetInputProps) {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<ScanConfig["profile"]>("normal");
  const [includeSubdomains, setIncludeSubdomains] = useState(true);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    onStart({
      target: target.trim(),
      profile,
      model_role: "reasoning",
      scope_config: {
        include_subdomains: includeSubdomains,
        ports: "top100",
        rate_limit: 10,
      },
    });
  };

  return (
    <Card className="border-border bg-card p-6">
      <form onSubmit={handleSubmit} className="space-y-5">
        <div className="space-y-2">
          <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Target
          </label>
          <div className="relative">
            <Crosshair className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com"
              className="pl-10 bg-background border-border h-11 text-base font-mono"
              disabled={loading}
            />
          </div>
        </div>

        <div className="flex gap-4">
          <div className="flex-1 space-y-2">
            <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Profile
            </label>
            <div className="flex gap-2">
              {(["stealth", "normal", "aggressive"] as const).map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setProfile(p)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                    profile === p
                      ? "bg-primary text-primary-foreground"
                      : "bg-secondary text-secondary-foreground hover:bg-accent"
                  }`}
                >
                  {p.charAt(0).toUpperCase() + p.slice(1)}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Subdomains
            </label>
            <button
              type="button"
              onClick={() => setIncludeSubdomains(!includeSubdomains)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                includeSubdomains
                  ? "bg-primary text-primary-foreground"
                  : "bg-secondary text-secondary-foreground"
              }`}
            >
              {includeSubdomains ? "Included" : "Excluded"}
            </button>
          </div>
        </div>

        <Button
          type="submit"
          disabled={!target.trim() || loading}
          className="w-full h-11 text-sm font-semibold cursor-pointer"
        >
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin mr-2" />
          ) : (
            <Crosshair className="h-4 w-4 mr-2" />
          )}
          {loading ? "Initializing..." : "Start Hunt"}
        </Button>
      </form>
    </Card>
  );
}
