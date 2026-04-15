"use client";

import { useState, useCallback } from "react";
import type { ScanConfig, ScanResponse, Finding } from "@/lib/types";
import { createScan, getFindings } from "@/lib/api";

export function useScan() {
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const startScan = useCallback(async (config: ScanConfig) => {
    setLoading(true);
    setError(null);
    try {
      const result = await createScan(config);
      setScan(result);
      return result;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to start scan";
      setError(msg);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshFindings = useCallback(async (scanId: string) => {
    try {
      const f = await getFindings(scanId);
      setFindings(f);
    } catch {
      /* swallow */
    }
  }, []);

  return { scan, findings, loading, error, startScan, refreshFindings, setScan };
}
