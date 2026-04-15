"use client";

import { useEffect, useState } from "react";
import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { getModels } from "@/lib/api";
import type { ModelInfo } from "@/lib/types";
import { Brain, Key } from "lucide-react";

export default function SettingsPage() {
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [apiKey, setApiKey] = useState("");

  useEffect(() => {
    getModels()
      .then((data) => setModels(data.models))
      .catch(() => {});
  }, []);

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 pl-56">
        <Header title="Settings" />
        <div className="p-6 max-w-2xl space-y-6">
          <Card className="p-5 border-border space-y-3">
            <div className="flex items-center gap-2">
              <Key className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">OpenRouter API Key</h3>
            </div>
            <Input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-or-..."
              className="font-mono bg-background"
            />
            <p className="text-xs text-muted-foreground">
              Get your key at openrouter.ai. Stored locally.
            </p>
          </Card>

          <Card className="p-5 border-border space-y-3">
            <div className="flex items-center gap-2">
              <Brain className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Available Models</h3>
            </div>
            <div className="space-y-2">
              {models.map((m) => (
                <div
                  key={m.id}
                  className="flex items-center justify-between rounded-md bg-background p-3 border border-border"
                >
                  <div>
                    <p className="text-sm font-medium">{m.name}</p>
                    <p className="text-xs text-muted-foreground font-mono">{m.id}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px]">{m.role}</Badge>
                    <span className="text-xs text-muted-foreground">
                      {(m.context_window / 1000).toFixed(0)}k ctx
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </main>
    </div>
  );
}
