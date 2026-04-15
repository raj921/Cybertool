import type { ScanConfig, ScanResponse, Finding, ModelInfo } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`API error ${res.status}: ${err}`);
  }
  return res.json();
}

export async function createScan(config: ScanConfig): Promise<ScanResponse> {
  return request<ScanResponse>("/api/scans", {
    method: "POST",
    body: JSON.stringify(config),
  });
}

export async function listScans(): Promise<ScanResponse[]> {
  return request<ScanResponse[]>("/api/scans");
}

export async function getScan(scanId: string): Promise<ScanResponse> {
  return request<ScanResponse>(`/api/scans/${scanId}`);
}

export async function getFindings(scanId: string): Promise<Finding[]> {
  return request<Finding[]>(`/api/scans/${scanId}/findings`);
}

export async function getModels(): Promise<{
  models: ModelInfo[];
  defaults: Record<string, string>;
}> {
  return request("/api/models");
}

export function getWsUrl(scanId: string): string {
  const wsBase = API_BASE.replace(/^http/, "ws");
  return `${wsBase}/ws/${scanId}`;
}
