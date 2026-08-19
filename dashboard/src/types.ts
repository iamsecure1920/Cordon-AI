// Types mirroring the /api/state JSON contract produced by
// easyhunt/tools/dashboard.py::collect_state()

export interface PhaseInfo {
  phase: string;
  state: "pending" | "running" | "ok" | "empty" | "failed";
  tool: string | null;
  seconds: number | null;
  findings: number | null;
  message: string | null;
  started_at?: string;
  finished_at?: string;
  input_?: string | null;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status =
  | "confirmed"
  | "candidate"
  | "needs_manual_review"
  | "untested"
  | "false_positive"
  | "dismissed";

export interface Finding {
  id: string | null;
  title: string;
  asset: string;
  severity: Severity;
  status: Status;
  phase: string;
  source_tool: string;
  cvss: number | null;
  confidence: number | null;
  evidence: unknown[];
  description?: string;
  cvss_vector?: string;
  remediation?: string;
  poc?: unknown;
  references?: string[];
  tags?: string[];
  first_seen?: string;
  last_seen?: string;
  validated?: boolean;
  is_canary?: boolean;
  how_found?: string;
  rule_id?: string;
  extra?: Record<string, unknown>;
}

export interface AssetItem {
  value: string;
  host: string | null;
  source: string | null;
  tags: string[];
  first_seen: string | null;
  attributes: Record<string, unknown>;
}

export interface CoverageRow {
  class: string;
  status: "not_attempted" | "detected" | "validated" | "disproven" | "n_a" | string;
  tool: string;
  note?: string;
  last_seen?: string;
}

export interface ToolUsage {
  tool: string;
  calls: number;
  phases: string[];
  outcomes: string[];
  findings: number;
  errors: number;
  last_ts: string | null;
}

export interface ActivityEvent {
  ts: string;
  phase: string;
  tool: string;
  outcome: string;
  findings: number;
}

export interface FalsePositive {
  id: string | null;
  title: string;
  asset: string | null;
  severity: Severity;
  source_tool: string;
  phase: string | null;
  status: string;
  reason: string;
  kind?: string;
  count?: number;
  context?: Record<string, unknown>;
}

export interface WorkspaceInfo {
  name: string;
  mtime: number;
  findings: number;
}

export interface ScopeInfo {
  name?: string;
  targets?: unknown[];
  in_scope?: unknown[];
  out_of_scope?: unknown[];
  [key: string]: unknown;
}

export interface DashboardState {
  workspace: string | null;
  workspace_name: string | null;
  generated_at: string;
  error?: string;
  scope: ScopeInfo | null;
  phases: Record<string, PhaseInfo>;
  phase_order: string[];
  running_phase: string | null;
  completed_count: number;
  findings: {
    total: number;
    by_severity: Partial<Record<Severity, number>>;
    by_status: Partial<Record<Status, number>>;
    findings: Finding[];
  };
  assets: Record<string, number>;
  assets_detail: { counts: Record<string, number>; items: Record<string, AssetItem[]> };
  coverage: { total: number; by_status: Record<string, number>; rows: CoverageRow[] };
  tools: ToolUsage[];
  false_positives: FalsePositive[];
  workspaces: WorkspaceInfo[];
  activity: ActivityEvent[];
  reports: string[];
}
