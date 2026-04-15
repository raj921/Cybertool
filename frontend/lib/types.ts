export interface ScanConfig {
  target: string;
  profile: "stealth" | "normal" | "aggressive";
  scope_config?: {
    include_subdomains: boolean;
    ports: string;
    rate_limit: number;
  };
  model_role: string;
}

export interface ScanResponse {
  id: string;
  target: string;
  status: string;
  profile: string;
  model_role: string;
  created_at: string;
  findings_count: number;
  scope_config?: Record<string, unknown>;
}

export interface Finding {
  id: string;
  vuln_type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: number;
  title: string;
  description: string;
  url: string;
  poc: string;
  cvss_score: number | null;
  verified: number;
  created_at: string;
}

export type AgentEventType =
  | "thinking"
  | "tool_start"
  | "tool_result"
  | "finding_raw"
  | "finding"
  | "chain"
  | "status"
  | "error";

export interface AgentEvent {
  type: AgentEventType;
  scan_id: string;
  text?: string;
  tool?: string;
  args?: Record<string, unknown>;
  result_preview?: string;
  data?: Record<string, unknown>;
  status?: string;
  summary?: Record<string, unknown>;
}

export interface ModelInfo {
  id: string;
  name: string;
  role: string;
  context_window: number;
  supports_tools: boolean;
}
