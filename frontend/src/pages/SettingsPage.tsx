import { useEffect, useState, useCallback } from "react";
import { Cog, KeyRound, Moon, Sliders, UserCog, Database, Server, Activity, Shield, Wifi, WifiOff, AlertCircle, CheckCircle2, XCircle, HelpCircle, RefreshCw } from "lucide-react";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/components/Toaster";
import { useAuth } from "@/contexts/AuthContext";
import { usePolling } from "@/hooks/usePolling";

export default function SettingsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [simulation, setSimulation] = useState(true);
  const [intervalSec, setIntervalSec] = useState(2.5);
  const [threshold, setThreshold] = useState(60);

  useEffect(() => {
    const stored = localStorage.getItem("ct_theme");
    if (stored === "light") {
      setTheme("light");
      document.documentElement.classList.remove("dark");
    }
  }, []);

  function toggleTheme(t: boolean) {
    setTheme(t ? "dark" : "light");
    document.documentElement.classList.toggle("dark", t);
    localStorage.setItem("ct_theme", t ? "dark" : "light");
  }

  function save() {
    toast({ title: "Settings saved", description: "Changes are persisted in this browser.", variant: "success" });
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Console Settings"
        description="Personalize your CipherTwin SOC environment."
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><UserCog className="h-4 w-4 text-cyber-cyan" />Profile</CardTitle>
        </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Label>Full name</Label>
              <Input value={user?.full_name ?? ""} readOnly />
          </div>
            <div>
              <Label>Email</Label>
              <Input value={user?.email ?? ""} readOnly />
          </div>
            <div>
              <Label>Role</Label>
              <Input value={user?.role ?? ""} readOnly />
          </div>
            <Button variant="cyber" size="sm"><KeyRound className="mr-1 h-3.5 w-3.5" />Rotate JWT secret</Button>
        </CardContent>
      </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Cog className="h-4 w-4 text-cyber-cyan" />Appearance</CardTitle>
        </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Moon className="h-4 w-4" />
                <div>
                  <div className="text-sm font-medium">Dark theme</div>
                  <div className="text-xs text-muted-foreground">Microsoft Defender-style dark mode</div>
              </div>
            </div>
              <Switch checked={theme === "dark"} onCheckedChange={toggleTheme} />
          </div>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-medium">Telemetry simulation</div>
                <div className="text-xs text-muted-foreground">Run the background worker that emits EDR-like events</div>
            </div>
              <Switch checked={simulation} onCheckedChange={setSimulation} />
          </div>
        </CardContent>
      </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Sliders className="h-4 w-4 text-cyber-cyan" />Risk Engine Tuning</CardTitle>
        </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Label>Telemetry interval seconds</Label>
              <Input type="number" step="0.5" value={intervalSec} onChange={(e) => setIntervalSec(Number(e.target.value))} />
          </div>
            <div>
              <Label>Deception trigger risk score</Label>
              <Input type="number" min={0} max={100} value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} />
          </div>
            <Button onClick={save} variant="cyber">Save settings</Button>
            <p className="text-xs text-muted-foreground">These are stored locally for the demo. A production deployment would sync them via the API</p>
        </CardContent>
      </Card>
    </div>

      {/* ── Module Integration Dashboard ─────────────────── */}
      <ModuleIntegrationDashboard />

      {/* ── Neo4j & Data Architecture Explanation ────────── */}
      <Neo4jExplanation />
  </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   MODULE INTEGRATION DASHBOARD
   ═══════════════════════════════════════════════════════════════ */
interface HealthData {
  status: string;
  services: Record<string, { status: string; message: string; [k: string]: unknown }>;
}

const SUBSYSTEM_META: Record<string, { icon: React.ReactNode; label: string; description: string }> = {
  fastapi:           { icon: <Server className="h-4 w-4" />,   label: "FastAPI Backend",       description: "Core REST API serving all endpoints" },
  sqlite:            { icon: <Database className="h-4 w-4" />, label: "SQLite Database",        description: "Primary persistent storage for all entities" },
  neo4j:             { icon: <Activity className="h-4 w-4" />, label: "Neo4j Graph DB",         description: "Graph projection for digital twin topology" },
  rabbitmq:          { icon: <Wifi className="h-4 w-4" />,     label: "RabbitMQ Broker",        description: "Async message queue for telemetry pipeline" },
  ml:                { icon: <Shield className="h-4 w-4" />,   label: "ML Risk Engine",         description: "Random Forest + Isolation Forest models" },
  deception:         { icon: <AlertCircle className="h-4 w-4" />, label: "Deception Engine",    description: "Honeytokens and adaptive decoy sessions" },
  cowrie:            { icon: <Activity className="h-4 w-4" />, label: "Cowrie Honeypot",        description: "SSH/Telnet honeypot log ingestion" },
  event_engine:      { icon: <Activity className="h-4 w-4" />, label: "Event Engine",           description: "Controlled event generation worker" },
  telemetry_worker:  { icon: <Activity className="h-4 w-4" />, label: "Telemetry Worker",       description: "Background pipeline processing events" },
};

function statusIcon(status: string) {
  switch (status) {
    case "HEALTHY":     return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
    case "DEGRADED":    return <AlertCircle className="h-4 w-4 text-yellow-400" />;
    case "UNAVAILABLE": return <XCircle className="h-4 w-4 text-red-400" />;
    case "NOT_CONFIGURED": return <HelpCircle className="h-4 w-4 text-slate-400" />;
    default:            return <HelpCircle className="h-4 w-4 text-slate-400" />;
  }
}

function statusBadge(status: string): "success" | "warning" | "danger" | "info" {
  switch (status) {
    case "HEALTHY":     return "success";
    case "DEGRADED":    return "warning";
    case "UNAVAILABLE": return "danger";
    default:            return "info";
  }
}

function ModuleIntegrationDashboard() {
  const health = usePolling<HealthData>("/system/health", 15000);
  const services = health.data?.services ?? {};
  const aggregate = health.data?.status ?? "LOADING";

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Server className="h-4 w-4 text-cyber-cyan" />
            Module Integration Status
          </CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant={aggregate === "HEALTHY" ? "success" : aggregate === "DEGRADED" ? "warning" : aggregate === "UNAVAILABLE" ? "danger" : "info"}>
              {aggregate}
            </Badge>
            {health.loading && <RefreshCw className="h-3 w-3 animate-spin text-muted-foreground" />}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {Object.entries(SUBSYSTEM_META).map(([key, meta]) => {
            const svc = services[key];
            const st = svc?.status ?? "LOADING";
            const msg = svc?.message ?? "Waiting for health check...";

            return (
              <div
                key={key}
                className="flex items-start gap-3 rounded-lg border border-border bg-muted/10 p-3 transition-colors hover:bg-muted/20"
              >
                <div className="mt-0.5 flex-shrink-0 text-cyber-cyan">{meta.icon}</div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold truncate">{meta.label}</span>
                    {statusIcon(st)}
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-0.5">{meta.description}</div>
                  <div className="mt-1 flex items-center gap-1.5">
                    <Badge variant={statusBadge(st)} className="text-[9px] px-1.5 py-0">{st}</Badge>
                    <span className="text-[10px] text-muted-foreground/70 truncate">{msg.slice(0, 60)}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        <p className="mt-3 text-[10px] text-muted-foreground">
          Statuses are checked live every 15 seconds. <strong>Healthy</strong> = connected and verified.{" "}
          <strong>Degraded</strong> = functional with reduced capability.{" "}
          <strong>Unavailable</strong> = service unreachable or errored.{" "}
          <strong>Not Configured</strong> = no connection settings provided.
        </p>
      </CardContent>
    </Card>
  );
}

/* ═══════════════════════════════════════════════════════════════
   NEO4J & DATA ARCHITECTURE EXPLANATION
   ═══════════════════════════════════════════════════════════════ */
function Neo4jExplanation() {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2">
          <Database className="h-4 w-4 text-cyber-cyan" />
          Data Architecture: Neo4j vs SQLite
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="text-sm text-muted-foreground space-y-2">
          <p>
            CipherTwin uses a <strong>dual-database architecture</strong> where SQLite is the
            authoritative source of truth and Neo4j provides an optional graph projection for
            network topology visualization and relationship queries.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {/* SQLite */}
          <div className="rounded-lg border border-blue-500/30 bg-blue-500/5 p-3">
            <div className="flex items-center gap-2 mb-2">
              <Database className="h-4 w-4 text-blue-400" />
              <span className="text-sm font-semibold text-blue-400">SQLite (Primary)</span>
            </div>
            <ul className="space-y-1 text-xs text-muted-foreground">
              <li>• User accounts, roles, and authentication</li>
              <li>• Telemetry events and risk scores</li>
              <li>• Security policies and optimization history</li>
              <li>• Decoy sessions and honeypot logs</li>
              <li>• Threat actor profiles and observations</li>
              <li>• Audit logs and analyst feedback</li>
              <li>• Twin nodes and relationships (canonical data)</li>
            </ul>
            <div className="mt-2 text-[10px] text-blue-300/70">
              Always available. No external service dependency.
            </div>
          </div>

          {/* Neo4j */}
          <div className="rounded-lg border border-violet-500/30 bg-violet-500/5 p-3">
            <div className="flex items-center gap-2 mb-2">
              <Activity className="h-4 w-4 text-violet-400" />
              <span className="text-sm font-semibold text-violet-400">Neo4j (Optional Graph)</span>
            </div>
            <ul className="space-y-1 text-xs text-muted-foreground">
              <li>• Network topology graph (devices, servers, honeypots)</li>
              <li>• Relationship traversal (connects_to, monitors, protects)</li>
              <li>• Digital Twin 3D/2D network visualization queries</li>
              <li>• Attack path analysis and shortest-path queries</li>
              <li>• Graph-based anomaly detection support</li>
            </ul>
            <div className="mt-2 text-[10px] text-violet-300/70">
              Optional. All features fall back to SQLite when Neo4j is unavailable.
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-border bg-muted/10 p-3">
          <div className="text-xs font-semibold mb-1.5">Which features depend on Neo4j?</div>
          <div className="grid grid-cols-1 gap-1.5 md:grid-cols-2 text-xs text-muted-foreground">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-3 w-3 text-emerald-400 flex-shrink-0" />
              <span><strong>Network Twin page</strong> — graph layout benefits from Neo4j but works with SQLite</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-3 w-3 text-emerald-400 flex-shrink-0" />
              <span><strong>Threat Intelligence</strong> — uses SQLite directly (no Neo4j dependency)</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-3 w-3 text-emerald-400 flex-shrink-0" />
              <span><strong>Risk Analytics</strong> — ML inference uses SQLite features only</span>
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-3 w-3 text-emerald-400 flex-shrink-0" />
              <span><strong>Quantum Optimization</strong> — policy re-optimization uses SQLite only</span>
            </div>
          </div>
          <p className="text-[10px] text-muted-foreground/60 mt-2">
            Neo4j enriches the Network Twin with native graph traversal. When Neo4j is unavailable,
            the Twin page fetches nodes and edges from SQLite and renders them identically in the
            frontend. No feature is blocked by Neo4j being offline.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
