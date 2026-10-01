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
  type: "user" | "device" | "laptop" | "desktop" | "tablet" | "server" | "database" | "application" | "iot" | "honeypot";
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
  techniques: string[];
  commands: string[];
  first_seen: string | null;
  last_seen: string | null;
  duration_seconds: number | null;
  return_activity: boolean;
  sessions: {
    id: number;
    session_id: string | null;
    first_seen: string | null;
    last_seen: string | null;
    protocols: string[];
    source_ports: Array<string | number>;
    ports: Array<string | number>;
  }[];
  severity: { label: "Reconnaissance only" | "Active probing" | "Elevated activity"; reason: string };
  description: string | null;
  status: "observed";
  event_source: string;
  event_count: number;
  session_count: number;
  protocols: string[];
  source_ports: Array<string | number>;
  ports: Array<string | number>;
  observations: HoneypotObservation[];
  technique_evidence: {
    technique_id: string;
    event_id: string | null;
    event_type: string | null;
    timestamp: string | null;
    request: string | null;
  }[];
  related_activity: {
    kind: string;
    actor_id: number;
    actor_ip: string;
    detail: string;
    session_ids?: number[];
  }[];
  tactics: Record<string, string[]>;
  external_intelligence: { status: "not_available"; provider: null };
}

export interface HoneypotObservation {
  timestamp: string;
  event_id: string;
  event_type: string;
  src_ip: string;
  src_port: string | number | null;
  protocol: string | null;
  dst_ip: string | null;
  dst_port: string | number | null;
  request: string | null;
  mitre_technique: string | null;
}

export interface DecoySession {
  id: number;
  timestamp: string | null;
  threat_id: number | null;
  decoy_type: string;
  fidelity?: "LOW" | "MEDIUM" | "HIGH";
  persona?: string | null;
  banner?: string | null;
  reason?: string | null;
  confidence?: number | null;
  mode?: "SIMULATED" | "COWRIE";
  actor: string | null;
  source_ip: string | null;
  activity: Array<HoneypotObservation | string>;
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
  last_triggered_at?: string | null;
  triggered_by?: string | null;
  alert_severity?: string;
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

export interface ServiceHealth {
  status: "HEALTHY" | "DEGRADED" | "UNAVAILABLE";
  message: string;
  [key: string]: any;
}

export interface SystemHealth {
  status: "HEALTHY" | "DEGRADED" | "UNAVAILABLE";
  timestamp: string;
  version: string;
  environment: string;
  services: Record<string, ServiceHealth>;
}

export interface AnalystFeedback {
  id: number;
  decision_id: number;
  analyst_id: string;
  original_prediction: string;
  analyst_label: "TRUE_POSITIVE" | "FALSE_POSITIVE" | "TRUE_NEGATIVE" | "FALSE_NEGATIVE";
  reason: string | null;
  timestamp: string | null;
}

export interface MLMetrics {
  model_version: string;
  model_type: string;
  total_predictions: number;
  normal_count: number;
  suspicious_count: number;
  malicious_count: number;
  average_confidence: number;
  holdout_accuracy: number;
  feedback_accuracy: number | null;
  false_positives: number;
  false_negatives: number;
  true_positives: number;
  true_negatives: number;
  total_feedback: number;
}

export interface PolicySimulation {
  total_evaluated: number;
  allow_count: number;
  restricted_count: number;
  deceive_count: number;
  deny_count: number;
  changed_decisions: number;
  details: {
    id: number;
    risk_score: number;
    current_decision: string;
    simulated_decision: string;
    flipped: boolean;
  }[];
  summary: string;
}

export interface BehaviourAnalysis {
  total_evaluated: number;
  normal_pct: number;
  suspicious_pct: number;
  anomalous_pct: number;
  malicious_pct: number;
  counts: {
    normal: number;
    suspicious: number;
    anomalous: number;
    malicious: number;
  };
  average_risk_score?: number;
  average_confidence?: number;
  summary?: string;
}
