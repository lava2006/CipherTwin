export interface UserOut {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: "admin" | "analyst";
}

export interface TwinNode {
  id: string;
  label: string;
  type: "user" | "device" | "laptop" | "desktop" | "tablet" | "server" | "database" | "application" | "iot";
  ip_address?: string;
  location?: string;
  department?: string;
  status: "online" | "offline" | "compromised";
  trust_score: number;
  risk_score: number;
  sensitivity: "low" | "medium" | "high" | "critical";
  os?: string;
  tags: string[];
  last_seen?: string;
}

export interface TwinEdge {
  source: string;
  target: string;
  relation: string;
  weight: number;
}

export interface TwinGraph {
  nodes: TwinNode[];
  edges: TwinEdge[];
}

export interface TelemetryEvent {
  id: number;
  timestamp: string | null;
  user_id: string | null;
  device_id: string | null;
  target_id: string | null;
  event_type: string;
  location: string | null;
  ip_address: string | null;
  status: string;
  risk_indicators: string[];
}

export interface RiskFactor {
  name: string;
  weight: number;
  score: number;
  contribution: number;
  description: string;
}

export interface RiskDecision {
  id: number;
  timestamp: string | null;
  telemetry_id: number | null;
  user_id: string | null;
  device_id: string | null;
  resource_id: string | null;
  risk_score: number;
  decision: "allow" | "restricted" | "deceive" | "deny";
  confidence: number;
  summary: string | null;
  factors: RiskFactor[];
}

export interface Policy {
  id: number;
  name: string;
  description: string;
  rule: string;
  priority: number;
  enabled: boolean;
  weight: number;
  false_positive_rate: number;
  false_negative_rate: number;
}

export interface PolicyImprovement {
  id: number;
  timestamp: string | null;
  algorithm: string;
  before_score: number;
  after_score: number;
  before_fp: number;
  after_fp: number;
  before_fn: number;
  after_fn: number;
  duration_ms: number;
  iterations: number;
  summary: string | null;
  changes: { policy: string; weight_before: number; weight_after: number; delta: number }[];
}

export interface Threat {
  id: number;
  actor_name: string;
  username: string | null;
  ip_address: string | null;
  risk_score: number;
  severity: "low" | "medium" | "high" | "critical";
  techniques: string[];
  commands: string[];
  first_seen: string | null;
  last_seen: string | null;
  description: string | null;
  status: "active" | "contained" | "neutralized";
}

export interface DecoySession {
  id: number;
  timestamp: string | null;
  threat_id: number | null;
  decoy_type: string;
  actor: string | null;
  source_ip: string | null;
  activity: string[];
  commands: string[];
  pages: string[];
  credentials_used: string | null;
  notes: string | null;
}

export interface Honeytoken {
  id: number;
  token_type: string;
  label: string;
  value: string;
  planted_on: string | null;
  triggered: boolean;
  created_at: string | null;
}

export interface AuditLog {
  id: number;
  timestamp: string | null;
  actor: string | null;
  action: string;
  target: string | null;
  details: string | null;
  severity: string;
  ip_address: string | null;
}

export interface OverviewStats {
  online_devices: number;
  offline_devices: number;
  compromised_assets: number;
  trust_relationships: number;
  active_sessions: number;
  risk_level: "low" | "medium" | "high" | "critical";
  total_users: number;
  total_telemetry_24h: number;
  threats_active: number;
  decoy_sessions: number;
  policies_count: number;
  risk_trend: { hour: string; score: number; count: number }[];
  telemetry_by_type: { event_type: string; count: number }[];
  top_attacked: { target_id: string; label: string; count: number }[];
  top_risky_users: {
    user_id: string;
    label: string;
    department: string;
    avg_risk: number;
    events: number;
  }[];
}

export interface PipelineStatus {
  running: boolean;
  events_processed: number;
  decisions_made: number;
  decoys_activated: number;
  threats_correlated: number;
  last_event_at: string | null;
}
