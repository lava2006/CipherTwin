import { useState, useMemo } from "react";
import {
  Crosshair, Radar, ShieldAlert, User, Search, ChevronLeft, ChevronRight,
  Activity, Terminal, Clock, Globe, FileText, AlertTriangle, ArrowUpDown,
  Filter, Download, Eye, Layers, Network, Shield, ChevronDown, ChevronUp,
  BarChart3,
} from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { Threat, HoneypotObservation } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { formatDateTime } from "@/lib/utils";

/* ── Constants ───────────────────────────────────────────────── */
const EVENTS_PER_PAGE = 20;
const SESSIONS_PER_PAGE = 25;

/* ── Dangerous command detection rules ───────────────────────── */
interface CommandFinding {
  command: string;
  timestamp: string | null;
  session_id: string | null;
  classification: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  why: string;
  intent: string;
  recommendation: string;
}

const COMMAND_RULES: {
  pattern: RegExp;
  classification: string;
  severity: CommandFinding["severity"];
  why: string;
  intent: string;
  recommendation: string;
}[] = [
  { pattern: /\b(uname|whoami|id|hostname|ifconfig|ip\s+addr|cat\s+\/etc\/(passwd|shadow|hosts)|ls\s+(\/|\/etc|\/home|\/root|\/var))\b/i, classification: "Reconnaissance", severity: "medium", why: "Enumerates system identity, users, or network config", intent: "Mapping the host for further exploitation", recommendation: "Monitor for lateral movement; restrict shell access" },
  { pattern: /\b(sudo|su\s+-|chmod\s+[0-7]*[4-7][0-7]*\s|chown\s+root|passwd)\b/i, classification: "Privilege Escalation", severity: "high", why: "Attempts to gain elevated privileges", intent: "Escalate from user to root or change ownership", recommendation: "Audit sudoers; enforce MFA for privilege escalation" },
  { pattern: /\b(wget|curl|fetch|tftp|scp|nc\s+-l|python\s+-m\s+http)\b/i, classification: "Suspicious Download", severity: "high", why: "Downloads or transfers files from external sources", intent: "Stage malware, tools, or exfiltrate data", recommendation: "Block outbound to unknown IPs; inspect downloaded files" },
  { pattern: /(\||\&\&|;)\s*(sh|bash|\/bin\/sh|python|perl|ruby|php)/i, classification: "Shell Chaining", severity: "high", why: "Chains commands into a new shell interpreter", intent: "Execute complex payloads or evade detection", recommendation: "Alert on piped shell invocations; use application whitelisting" },
  { pattern: /\b(crontab|at\s+|systemctl\s+enable|\.bashrc|\.profile|rc\.local|init\.d)\b/i, classification: "Persistence", severity: "critical", why: "Installs persistent access mechanism", intent: "Maintain long-term access to the compromised host", recommendation: "Audit cron jobs and startup scripts; deploy file integrity monitoring" },
  { pattern: /\b(rm\s+-rf|mkfs|dd\s+if=|shred|wipefs|>\s*\/dev\/sd)\b/i, classification: "Destructive", severity: "critical", why: "Destroys data, filesystems, or disk contents", intent: "Sabotage, anti-forensics, or ransom leverage", recommendation: "Isolate host immediately; preserve forensic evidence" },
  { pattern: /\b(nmap|masscan|zmap|nikto|dirb|gobuster|sqlmap|hydra|john|hashcat)\b/i, classification: "Attack Tools", severity: "critical", why: "Uses offensive security or brute-force tools", intent: "Scan, enumerate, or brute-force targets", recommendation: "Block tool execution; investigate source IP for further compromise" },
  { pattern: /\b(iptables\s+-F|ufw\s+disable|setenforce\s+0|apparmor.*teardown)\b/i, classification: "Defense Evasion", severity: "high", why: "Disables firewall or security controls", intent: "Remove defensive barriers before further exploitation", recommendation: "Alert on security control changes; enforce immutable configs" },
  { pattern: /\b(cat|head|tail|less|more|strings)\s+.*\.(pem|key|crt|cert|p12|pfx|kdbx|env|conf|cfg|ini|json|yaml|yml|xml|sql|db|sqlite)\b/i, classification: "Credential/Data Access", severity: "high", why: "Reads sensitive configuration, key, or database files", intent: "Harvest credentials or sensitive application data", recommendation: "Encrypt secrets at rest; use vault-based secret management" },
  { pattern: /\b(ssh\s+|sshpass|psexec|wmic|net\s+use|rdesktop|xfreerdp)\b/i, classification: "Lateral Movement", severity: "high", why: "Initiates connections to other hosts", intent: "Pivot to additional systems in the network", recommendation: "Segment network; monitor east-west traffic; restrict SSH keys" },
];

function analyzeCommands(threat: Threat): CommandFinding[] {
  const findings: CommandFinding[] = [];
  for (const cmd of threat.commands) {
    for (const rule of COMMAND_RULES) {
      if (rule.pattern.test(cmd)) {
        findings.push({
          command: cmd,
          timestamp: null,
          session_id: null,
          classification: rule.classification,
          severity: rule.severity,
          why: rule.why,
          intent: rule.intent,
          recommendation: rule.recommendation,
        });
        break; // one match per command
      }
    }
  }
  // Also check observations with request field for command-like content
  for (const obs of threat.observations) {
    if (obs.request && obs.event_id?.includes("command")) {
      for (const rule of COMMAND_RULES) {
        if (rule.pattern.test(obs.request)) {
          findings.push({
            command: obs.request,
            timestamp: obs.timestamp,
            session_id: obs.event_id,
            classification: rule.classification,
            severity: rule.severity,
            why: rule.why,
            intent: rule.intent,
            recommendation: rule.recommendation,
          });
          break;
        }
      }
    }
  }
  return findings;
}

/* ── Docker/private IP detection ─────────────────────────────── */
function isPrivateOrDockerIP(ip: string | null): { isPrivate: boolean; context: string } {
  if (!ip) return { isPrivate: false, context: "" };
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return { isPrivate: true, context: "Docker container network (172.16.0.0/12). This is likely the Docker bridge gateway, not an external attacker." };
  if (/^10\./.test(ip)) return { isPrivate: true, context: "Private network (10.0.0.0/8). This address is internal to your infrastructure." };
  if (/^192\.168\./.test(ip)) return { isPrivate: true, context: "Private network (192.168.0.0/16). This address is internal to your local network." };
  if (/^127\./.test(ip)) return { isPrivate: true, context: "Loopback address. This traffic originated from the same host." };
  return { isPrivate: false, context: "Public IP address." };
}

/* ── Severity colors ─────────────────────────────────────────── */
function severityColor(severity: string): string {
  switch (severity) {
    case "critical": return "text-red-400 bg-red-500/10 border-red-500/30";
    case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
    case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
    case "low": return "text-blue-400 bg-blue-500/10 border-blue-500/30";
    default: return "text-slate-400 bg-slate-500/10 border-slate-500/30";
  }
}

function severityBadgeVariant(label: string): "danger" | "warning" | "success" {
  if (label === "Elevated activity") return "danger";
  if (label === "Active probing") return "warning";
  return "success";
}

/* ═══════════════════════════════════════════════════════════════
   MAIN PAGE
   ═══════════════════════════════════════════════════════════════ */
export default function ThreatsPage() {
  const threats = usePolling<Threat[]>("/threats", 6000);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [actorSearch, setActorSearch] = useState("");

  const list = threats.data ?? [];
  const filteredList = list.filter(
    (t) =>
      t.actor_name.toLowerCase().includes(actorSearch.toLowerCase()) ||
      (t.ip_address ?? "").includes(actorSearch),
  );
  const active = list.find((t) => t.id === selectedId) || list[0];

  // Summary stats
  const totalEvents = list.reduce((s, t) => s + t.event_count, 0);
  const totalSessions = list.reduce((s, t) => s + t.session_count, 0);
  const suspiciousEvents = list.reduce(
    (s, t) => s + t.observations.filter((o) => o.event_id?.includes("login") || o.event_id?.includes("command")).length,
    0,
  );
  const highSeverity = list.filter((t) => t.severity.label === "Elevated activity" || t.severity.label === "Active probing").length;

  function handleExport() {
    if (!active) return;
    const content = JSON.stringify(active, null, 2);
    const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `threat-evidence-${active.ip_address ?? active.id}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <div className="space-y-4">
      <SectionHeader
        title="Threat Intelligence"
        description="Observed Cowrie honeypot sources and event evidence. External intelligence is shown only when a provider is configured."
      />

      {/* ── Summary KPI Cards ─────────────────────────────── */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <KpiMini icon={<Activity className="h-4 w-4" />} label="Observed Events" value={totalEvents} color="cyan" />
        <KpiMini icon={<Layers className="h-4 w-4" />} label="Cowrie Sessions" value={totalSessions} color="blue" />
        <KpiMini icon={<AlertTriangle className="h-4 w-4" />} label="Suspicious Events" value={suspiciousEvents} color="yellow" />
        <KpiMini icon={<ShieldAlert className="h-4 w-4" />} label="High-Severity Actors" value={highSeverity} color="red" />
      </div>

      {/* ── Main Layout: Actor Panel + Investigation ───── */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[320px_1fr]">
        {/* ── Actor List Panel ──────────────────────────── */}
        <Card className="h-fit max-h-[calc(100vh-220px)] overflow-hidden flex flex-col">
          <CardHeader className="pb-2 flex-shrink-0">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Radar className="h-4 w-4 text-cyber-cyan" />
              Threat Actors ({list.length})
            </CardTitle>
            <div className="relative mt-2">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search IP or name..."
                value={actorSearch}
                onChange={(e) => setActorSearch(e.target.value)}
                className="w-full rounded-md border border-border bg-muted/30 py-2 pl-8 pr-3 text-xs placeholder:text-muted-foreground focus:border-cyber-cyan/50 focus:outline-none focus:ring-1 focus:ring-cyber-cyan/30"
              />
            </div>
          </CardHeader>
          <CardContent className="flex-1 overflow-y-auto space-y-1.5 pb-3">
            {threats.loading && !list.length ? (
              Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)
            ) : (
              filteredList.map((t) => {
                const isActive = selectedId === t.id || (!selectedId && t === list[0]);
                return (
                  <button
                    key={t.id}
                    onClick={() => setSelectedId(t.id)}
                    className={`w-full text-left rounded-lg border p-2.5 transition-all ${
                      isActive
                        ? "border-cyber-cyan/50 bg-cyber-cyan/10 shadow-sm shadow-cyber-cyan/10"
                        : "border-border bg-card/40 hover:bg-muted/30 hover:border-muted-foreground/20"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        <Crosshair className="h-3.5 w-3.5 text-cyber-cyan flex-shrink-0" />
                        <div className="min-w-0">
                          <div className="text-sm font-semibold truncate">{t.actor_name}</div>
                          <div className="text-[10px] text-muted-foreground truncate">{t.ip_address ?? "No IP"}</div>
                        </div>
                      </div>
                      <Badge variant={severityBadgeVariant(t.severity.label)} className="text-[10px] flex-shrink-0">
                        {t.severity.label}
                      </Badge>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between text-[10px]">
                      <span className="text-muted-foreground">{t.session_count} sessions</span>
                      <span className="font-bold text-cyber-cyan">{t.event_count} events</span>
                    </div>
                    {t.techniques.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-0.5">
                        {t.techniques.slice(0, 3).map((tid) => (
                          <Badge key={tid} variant="violet" className="px-1 py-0 font-mono text-[9px]">{tid}</Badge>
                        ))}
                        {t.techniques.length > 3 && (
                          <Badge variant="violet" className="px-1 py-0 text-[9px]">+{t.techniques.length - 3}</Badge>
                        )}
                      </div>
                    )}
                  </button>
                );
              })
            )}
            {filteredList.length === 0 && !threats.loading && (
              <p className="text-xs text-muted-foreground text-center py-4">
                {actorSearch ? "No matching actors" : "No threats correlated yet"}
              </p>
            )}
          </CardContent>
        </Card>

        {/* ── Investigation Workspace ──────────────────── */}
        <Card className="min-h-[600px]">
          <CardContent className="p-0">
            {active ? (
              <InvestigationConsole threat={active} onExport={handleExport} />
            ) : (
              <div className="flex items-center justify-center h-[400px]">
                <p className="text-sm text-muted-foreground">Select a threat actor to begin investigation</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   INVESTIGATION CONSOLE — 7-Tab Layout
   ═══════════════════════════════════════════════════════════════ */
function InvestigationConsole({ threat, onExport }: { threat: Threat; onExport: () => void }) {
  const ipInfo = isPrivateOrDockerIP(threat.ip_address);
  const findings = useMemo(() => analyzeCommands(threat), [threat]);

  return (
    <div className="p-4 space-y-4">
      {/* ── Actor Header ──────────────────────────────── */}
      <div className="flex items-start gap-4">
        <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-cyber-cyan/20 text-cyber-cyan flex-shrink-0">
          <Crosshair className="h-5 w-5" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-lg font-bold truncate">{threat.actor_name}</h2>
            <Badge variant={severityBadgeVariant(threat.severity.label)} title={threat.severity.reason}>
              {threat.severity.label}
            </Badge>
            <Badge variant="info">Observed by honeypot</Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">{threat.description}</p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <Button size="sm" variant="cyber" onClick={onExport}>
            <Download className="mr-1 h-3.5 w-3.5" />Export IOC
          </Button>
        </div>
      </div>

      {/* ── Source Attribution Warning ─────────────────── */}
      {ipInfo.isPrivate && (
        <div className="flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-3">
          <AlertTriangle className="h-4 w-4 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-xs font-semibold text-yellow-400">Source Attribution Notice</div>
            <div className="text-xs text-yellow-300/80 mt-0.5">
              <code className="font-mono bg-yellow-500/10 px-1 rounded">{threat.ip_address}</code> — {ipInfo.context}{" "}
              This IP should not be treated as an external threat indicator. Events from this address represent
              traffic traversing the Docker network, not direct attacks from the internet.
            </div>
          </div>
        </div>
      )}

      {/* ── Tabbed Investigation ──────────────────────── */}
      <Tabs defaultValue="overview">
        <TabsList className="flex flex-wrap h-auto gap-1">
          <TabsTrigger value="overview" className="text-xs gap-1"><Eye className="h-3 w-3" />Overview</TabsTrigger>
          <TabsTrigger value="events" className="text-xs gap-1"><Activity className="h-3 w-3" />Event Explorer</TabsTrigger>
          <TabsTrigger value="commands" className="text-xs gap-1"><Terminal className="h-3 w-3" />Command Analysis</TabsTrigger>
          <TabsTrigger value="timeline" className="text-xs gap-1"><Clock className="h-3 w-3" />Timeline</TabsTrigger>
          <TabsTrigger value="sessions" className="text-xs gap-1"><Layers className="h-3 w-3" />Sessions</TabsTrigger>
          <TabsTrigger value="network" className="text-xs gap-1"><Network className="h-3 w-3" />Network</TabsTrigger>
          <TabsTrigger value="evidence" className="text-xs gap-1"><FileText className="h-3 w-3" />Evidence</TabsTrigger>
        </TabsList>

        <TabsContent value="overview"><OverviewTab threat={threat} findings={findings} /></TabsContent>
        <TabsContent value="events"><EventExplorerTab threat={threat} /></TabsContent>
        <TabsContent value="commands"><CommandAnalysisTab threat={threat} findings={findings} /></TabsContent>
        <TabsContent value="timeline"><TimelineTab threat={threat} /></TabsContent>
        <TabsContent value="sessions"><SessionExplorerTab threat={threat} /></TabsContent>
        <TabsContent value="network"><NetworkIndicatorsTab threat={threat} /></TabsContent>
        <TabsContent value="evidence"><EvidenceTab threat={threat} /></TabsContent>
      </Tabs>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   TAB 1 — OVERVIEW
   ═══════════════════════════════════════════════════════════════ */
function OverviewTab({ threat, findings }: { threat: Threat; findings: CommandFinding[] }) {
  const eventTypes = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const o of threat.observations) {
      const key = o.event_type || o.event_id || "unknown";
      counts[key] = (counts[key] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [threat.observations]);

  return (
    <div className="space-y-4">
      {/* Key metrics */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Field label="Source IP" value={threat.ip_address ?? "N/A"} />
        <Field label="Observed Events" value={String(threat.event_count)} />
        <Field label="Cowrie Sessions" value={`${threat.session_count}${threat.return_activity ? " · return activity" : ""}`} />
        <Field label="Observed Span" value={formatDuration(threat.duration_seconds)} />
        <Field label="First Seen" value={formatDateTime(threat.first_seen)} />
        <Field label="Last Seen" value={formatDateTime(threat.last_seen)} />
        <Field label="Protocol" value={threat.protocols.join(", ") || "Not recorded"} />
        <Field label="Commands Recorded" value={String(threat.commands.length)} />
      </div>

      {/* Classification */}
      <div className="text-xs text-muted-foreground rounded border border-border bg-muted/10 p-2.5">
        <span className="font-semibold text-muted-foreground/80">Classification:</span> {threat.severity.reason}
        {threat.return_activity && " Return activity means distinct Cowrie session IDs were observed for this source IP."}
      </div>

      {/* Event type breakdown */}
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Event Type Breakdown</h4>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
          {eventTypes.map(([type, count]) => (
            <div key={type} className="flex items-center justify-between rounded border border-border bg-muted/20 p-2 text-xs">
              <span className="font-mono text-cyber-cyan">{type}</span>
              <Badge variant="info" className="text-[10px]">{count}</Badge>
            </div>
          ))}
        </div>
      </div>

      {/* Tactics & Techniques */}
      {threat.techniques.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">MITRE ATT&CK Techniques</h4>
          <div className="flex flex-wrap gap-1.5">
            {threat.techniques.map((tid) => (
              <Badge key={tid} variant="violet" className="font-mono">{tid}</Badge>
            ))}
          </div>
        </div>
      )}

      {Object.keys(threat.tactics).length > 0 && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Tactics Breakdown</h4>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            {Object.entries(threat.tactics).map(([tactic, techs]) => (
              <div key={tactic} className="rounded border border-border bg-card/40 p-2.5">
                <div className="text-xs font-semibold text-cyber-cyan">{tactic}</div>
                <div className="mt-1 space-y-0.5 text-xs">
                  {(techs as string[]).map((t, i) => (
                    <div key={i} className="font-mono text-muted-foreground">{t}</div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Command findings summary */}
      {findings.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
            <AlertTriangle className="inline h-3 w-3 mr-1 text-red-400" />
            Dangerous Command Findings ({findings.length})
          </h4>
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
            {[...new Set(findings.map((f) => f.classification))].map((cls) => {
              const count = findings.filter((f) => f.classification === cls).length;
              const sev = findings.find((f) => f.classification === cls)!.severity;
              return (
                <div key={cls} className={`rounded border p-2 text-xs ${severityColor(sev)}`}>
                  <div className="font-semibold">{cls}</div>
                  <div className="text-lg font-bold">{count}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* External intelligence */}
      <div className="rounded border border-border bg-muted/10 p-3 text-sm">
        <div className="font-semibold flex items-center gap-2">
          <Globe className="h-3.5 w-3.5" />External Intelligence: Not Available
        </div>
        <div className="mt-1 text-xs text-muted-foreground">
          No external provider is configured. This profile contains observed honeypot evidence only.
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   TAB 2 — EVENT EXPLORER (paginated, searchable)
   ═══════════════════════════════════════════════════════════════ */
function EventExplorerTab({ threat }: { threat: Threat }) {
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const eventTypes = useMemo(() => {
    const types = new Set(threat.observations.map((o) => o.event_type || o.event_id));
    return ["all", ...Array.from(types).sort()];
  }, [threat.observations]);

  const filtered = useMemo(() => {
    let items = threat.observations;
    if (typeFilter !== "all") items = items.filter((o) => (o.event_type || o.event_id) === typeFilter);
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(
        (o) =>
          o.event_id?.toLowerCase().includes(q) ||
          o.event_type?.toLowerCase().includes(q) ||
          o.request?.toLowerCase().includes(q) ||
          o.src_ip?.toLowerCase().includes(q) ||
          String(o.src_port).includes(q),
      );
    }
    return items;
  }, [threat.observations, search, typeFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / EVENTS_PER_PAGE));
  const safePage = Math.min(page, totalPages - 1);
  const pageItems = filtered.slice(safePage * EVENTS_PER_PAGE, (safePage + 1) * EVENTS_PER_PAGE);

  return (
    <div className="space-y-3">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search events (ID, type, request, IP, port)..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            className="w-full rounded-md border border-border bg-muted/30 py-2 pl-8 pr-3 text-xs placeholder:text-muted-foreground focus:border-cyber-cyan/50 focus:outline-none focus:ring-1 focus:ring-cyber-cyan/30"
          />
        </div>
        <div className="flex items-center gap-1">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setPage(0); }}
            className="rounded-md border border-border bg-muted/30 py-1.5 px-2 text-xs focus:border-cyber-cyan/50 focus:outline-none"
          >
            {eventTypes.map((t) => (
              <option key={t} value={t}>{t === "all" ? "All types" : t}</option>
            ))}
          </select>
        </div>
        <Badge variant="info" className="text-[10px]">{filtered.length} / {threat.observations.length} events</Badge>
      </div>

      {/* Event list */}
      <div className="space-y-1.5">
        {pageItems.map((event, index) => (
          <EventCard key={`${event.event_id}-${event.timestamp}-${safePage}-${index}`} event={event} index={safePage * EVENTS_PER_PAGE + index + 1} />
        ))}
        {pageItems.length === 0 && (
          <p className="text-xs text-muted-foreground text-center py-6">No events match the current filter.</p>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <Button size="sm" variant="outline" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>
            <ChevronLeft className="h-3.5 w-3.5 mr-1" />Previous
          </Button>
          <span className="text-xs text-muted-foreground">
            Page {safePage + 1} of {totalPages}
          </span>
          <Button size="sm" variant="outline" disabled={safePage >= totalPages - 1} onClick={() => setPage(safePage + 1)}>
            Next<ChevronRight className="h-3.5 w-3.5 ml-1" />
          </Button>
        </div>
      )}
    </div>
  );
}

function EventCard({ event, index }: { event: HoneypotObservation; index: number }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-md border border-border bg-muted/10 p-2.5 text-xs hover:border-muted-foreground/30 transition-colors">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-[10px] text-muted-foreground/60 font-mono w-6 text-right flex-shrink-0">#{index}</span>
          <Badge variant={event.event_id?.includes("connect") ? "info" : event.event_id?.includes("login") ? "warning" : event.event_id?.includes("command") ? "danger" : "success"} className="text-[10px] flex-shrink-0">
            {event.event_type || "event"}
          </Badge>
          <span className="font-mono text-muted-foreground truncate">{event.event_id}</span>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-muted-foreground">{formatDateTime(event.timestamp)}</span>
          <button onClick={() => setExpanded(!expanded)} className="text-muted-foreground hover:text-cyber-cyan">
            {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </button>
        </div>
      </div>
      <div className="mt-1 text-muted-foreground pl-8">
        {event.src_ip}{event.src_port != null ? `:${event.src_port}` : ""}
        {event.dst_ip ? ` → ${event.dst_ip}` : ""}
        {event.dst_port != null ? `:${event.dst_port}` : ""}
        {event.protocol ? ` [${event.protocol}]` : ""}
      </div>
      {expanded && event.request && (
        <div className="mt-2 pl-8">
          <div className="text-[10px] uppercase text-muted-foreground/60 mb-0.5">Raw Evidence</div>
          <code className="block break-all rounded bg-black/30 p-2 font-mono text-[11px] text-emerald-300 border border-border">{event.request}</code>
          {event.mitre_technique && (
            <div className="mt-1">
              <Badge variant="violet" className="font-mono text-[10px]">{event.mitre_technique}</Badge>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   TAB 3 — COMMAND ANALYSIS
   ═══════════════════════════════════════════════════════════════ */
function CommandAnalysisTab({ threat, findings }: { threat: Threat; findings: CommandFinding[] }) {
  if (threat.commands.length === 0 && findings.length === 0) {
    return (
      <div className="text-center py-12 space-y-3">
        <Terminal className="h-10 w-10 mx-auto text-muted-foreground/30" />
        <div>
          <p className="text-sm font-semibold text-muted-foreground">No Commands Recorded</p>
          <p className="text-xs text-muted-foreground/70 mt-1">
            This actor's sessions were limited to connection-level events (connect/disconnect).
            No interactive shell sessions or command input were captured by the honeypot.
          </p>
          <p className="text-xs text-muted-foreground/50 mt-2">
            This pattern is consistent with automated scanning or port probing, where the attacker
            connects briefly to verify service availability without engaging in interactive exploitation.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Raw commands */}
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
          Observed Commands ({threat.commands.length})
        </h4>
        <div className="rounded-lg border border-border bg-black/30 p-3 font-mono text-xs space-y-0.5 max-h-[300px] overflow-y-auto">
          {threat.commands.map((c, i) => (
            <div key={i} className="text-emerald-300">
              <span className="text-muted-foreground/50 mr-2">{String(i + 1).padStart(3, " ")}.</span>
              <span className="text-emerald-400">$</span> {c}
            </div>
          ))}
        </div>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
            <AlertTriangle className="inline h-3 w-3 mr-1 text-red-400" />
            Dangerous Command Findings ({findings.length})
          </h4>
          <div className="space-y-2">
            {findings.map((f, i) => (
              <div key={i} className={`rounded-lg border p-3 text-xs ${severityColor(f.severity)}`}>
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <Badge className={`text-[10px] uppercase ${severityColor(f.severity)}`}>{f.severity}</Badge>
                    <span className="font-semibold">{f.classification}</span>
                  </div>
                  {f.timestamp && <span className="text-[10px]">{formatDateTime(f.timestamp)}</span>}
                </div>
                <code className="block break-all rounded bg-black/30 p-2 font-mono text-emerald-300 mb-2">{f.command}</code>
                <div className="grid grid-cols-1 gap-1 md:grid-cols-3 text-[11px]">
                  <div><span className="font-semibold">Why suspicious:</span> {f.why}</div>
                  <div><span className="font-semibold">Attacker intent:</span> {f.intent}</div>
                  <div><span className="font-semibold">Recommended action:</span> {f.recommendation}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   TAB 4 — ATTACK TIMELINE
   ═══════════════════════════════════════════════════════════════ */
function TimelineTab({ threat }: { threat: Threat }) {
  const [limit, setLimit] = useState(50);

  const sorted = useMemo(
    () => [...threat.observations].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()),
    [threat.observations],
  );
  const shown = sorted.slice(0, limit);

  // Time clusters (group events within 5-second windows)
  const clusters = useMemo(() => {
    const result: { time: string; events: HoneypotObservation[] }[] = [];
    let currentCluster: HoneypotObservation[] = [];
    let clusterStart = 0;

    for (const obs of shown) {
      const t = new Date(obs.timestamp).getTime();
      if (currentCluster.length === 0 || t - clusterStart < 5000) {
        if (currentCluster.length === 0) clusterStart = t;
        currentCluster.push(obs);
      } else {
        result.push({ time: formatDateTime(currentCluster[0].timestamp), events: currentCluster });
        currentCluster = [obs];
        clusterStart = t;
      }
    }
    if (currentCluster.length > 0) {
      result.push({ time: formatDateTime(currentCluster[0].timestamp), events: currentCluster });
    }
    return result;
  }, [shown]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Chronological Timeline · {sorted.length} events
        </h4>
        <Badge variant="info" className="text-[10px]">
          {clusters.length} time clusters (5s window)
        </Badge>
      </div>

      <div className="relative pl-6 border-l-2 border-cyber-cyan/20 space-y-3 max-h-[500px] overflow-y-auto">
        {clusters.map((cluster, ci) => (
          <div key={ci} className="relative">
            <div className="absolute -left-[31px] top-0 h-3 w-3 rounded-full bg-cyber-cyan/60 border-2 border-background" />
            <div className="text-[10px] text-cyber-cyan font-mono mb-1">{cluster.time}</div>
            <div className="space-y-0.5">
              {cluster.events.map((evt, ei) => (
                <div key={ei} className="rounded border border-border bg-muted/10 p-1.5 text-[11px] flex items-center gap-2">
                  <Badge
                    variant={evt.event_id?.includes("connect") ? "info" : evt.event_id?.includes("closed") ? "success" : "warning"}
                    className="text-[9px] flex-shrink-0"
                  >
                    {evt.event_type}
                  </Badge>
                  <span className="font-mono text-muted-foreground truncate">
                    {evt.src_ip}:{evt.src_port} → {evt.dst_ip}:{evt.dst_port}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {limit < sorted.length && (
        <Button size="sm" variant="outline" onClick={() => setLimit(limit + 100)} className="w-full">
          Load more ({sorted.length - limit} remaining)
        </Button>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   TAB 5 — SESSION EXPLORER
   ═══════════════════════════════════════════════════════════════ */
function SessionExplorerTab({ threat }: { threat: Threat }) {
  const [page, setPage] = useState(0);
  const [expandedSession, setExpandedSession] = useState<number | null>(null);

  const totalPages = Math.max(1, Math.ceil(threat.sessions.length / SESSIONS_PER_PAGE));
  const safePage = Math.min(page, totalPages - 1);
  const pageSessions = threat.sessions.slice(safePage * SESSIONS_PER_PAGE, (safePage + 1) * SESSIONS_PER_PAGE);

  // Map observations to sessions by matching session_id in the request text
  const sessionEvents = useMemo(() => {
    const map: Record<string, HoneypotObservation[]> = {};
    for (const obs of threat.observations) {
      if (obs.request) {
        const match = obs.request.match(/\[session:\s*([a-f0-9]+)\]/i);
        if (match) {
          const sid = match[1];
          if (!map[sid]) map[sid] = [];
          map[sid].push(obs);
        }
      }
    }
    return map;
  }, [threat.observations]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Cowrie Sessions ({threat.sessions.length})
        </h4>
        {totalPages > 1 && (
          <span className="text-[10px] text-muted-foreground">Page {safePage + 1} of {totalPages}</span>
        )}
      </div>

      <div className="space-y-1.5">
        {pageSessions.map((session) => {
          const events = sessionEvents[session.session_id ?? ""] ?? [];
          const isExpanded = expandedSession === session.id;

          return (
            <div key={session.id} className="rounded-lg border border-border bg-muted/10 text-xs overflow-hidden">
              <button
                className="w-full text-left p-2.5 flex items-center justify-between hover:bg-muted/20 transition-colors"
                onClick={() => setExpandedSession(isExpanded ? null : session.id)}
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono text-cyber-cyan">{session.session_id ?? session.id}</span>
                  <Badge variant="info" className="text-[9px]">{session.protocols.join(", ")}</Badge>
                  <span className="text-muted-foreground">port {session.ports.join(", ")}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-muted-foreground">{formatDateTime(session.first_seen)}</span>
                  <span className="text-muted-foreground">{events.length} events</span>
                  {isExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                </div>
              </button>
              {isExpanded && (
                <div className="border-t border-border bg-black/20 p-3 space-y-2">
                  <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
                    <Field label="Session ID" value={session.session_id ?? "N/A"} />
                    <Field label="Start" value={formatDateTime(session.first_seen)} />
                    <Field label="End" value={formatDateTime(session.last_seen)} />
                    <Field label="Source Port" value={session.source_ports.join(", ") || "N/A"} />
                  </div>
                  {events.length > 0 ? (
                    <div className="space-y-1 mt-2">
                      <div className="text-[10px] uppercase text-muted-foreground/60">Chronological Events</div>
                      {events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()).map((evt, i) => (
                        <div key={i} className="rounded border border-border bg-muted/10 p-1.5 text-[11px]">
                          <span className="font-mono text-muted-foreground/60 mr-2">{formatDateTime(evt.timestamp)}</span>
                          <Badge variant={evt.event_id?.includes("connect") ? "info" : "success"} className="text-[9px] mr-1">{evt.event_type}</Badge>
                          {evt.request && <code className="text-emerald-300 break-all">{evt.request}</code>}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[10px] text-muted-foreground">No detailed events matched for this session ID.</p>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <Button size="sm" variant="outline" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>
            <ChevronLeft className="h-3.5 w-3.5 mr-1" />Previous
          </Button>
          <span className="text-xs text-muted-foreground">Page {safePage + 1} of {totalPages}</span>
          <Button size="sm" variant="outline" disabled={safePage >= totalPages - 1} onClick={() => setPage(safePage + 1)}>
            Next<ChevronRight className="h-3.5 w-3.5 ml-1" />
          </Button>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   TAB 6 — NETWORK INDICATORS (compact, expandable)
   ═══════════════════════════════════════════════════════════════ */
function NetworkIndicatorsTab({ threat }: { threat: Threat }) {
  const [showAllSrcPorts, setShowAllSrcPorts] = useState(false);
  const [showAllDstPorts, setShowAllDstPorts] = useState(false);

  const srcPortsPreview = threat.source_ports.slice(0, 10);
  const dstPortsPreview = threat.ports.slice(0, 10);

  return (
    <div className="space-y-4">
      {/* Protocols */}
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Observed Protocols</h4>
        <div className="flex flex-wrap gap-2">
          {threat.protocols.length ? (
            threat.protocols.map((p) => (
              <Badge key={p} variant="info" className="font-mono">{p}</Badge>
            ))
          ) : (
            <span className="text-xs text-muted-foreground">Not recorded</span>
          )}
        </div>
      </div>

      {/* Destination ports */}
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
          Destination Ports ({threat.ports.length})
        </h4>
        <div className="flex flex-wrap gap-1.5">
          {(showAllDstPorts ? threat.ports : dstPortsPreview).map((p, i) => (
            <Badge key={i} variant="violet" className="font-mono text-[10px]">{p}</Badge>
          ))}
          {threat.ports.length > 10 && !showAllDstPorts && (
            <button
              onClick={() => setShowAllDstPorts(true)}
              className="text-[10px] text-cyber-cyan hover:underline"
            >
              +{threat.ports.length - 10} more
            </button>
          )}
          {showAllDstPorts && threat.ports.length > 10 && (
            <button onClick={() => setShowAllDstPorts(false)} className="text-[10px] text-cyber-cyan hover:underline">
              collapse
            </button>
          )}
        </div>
      </div>

      {/* Source ports */}
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
          Source Ports ({threat.source_ports.length})
          <span className="ml-2 text-[10px] font-normal text-muted-foreground/60">Ephemeral ports used by the client</span>
        </h4>
        <div className="rounded border border-border bg-muted/10 p-2.5">
          {threat.source_ports.length <= 10 ? (
            <div className="flex flex-wrap gap-1.5">
              {threat.source_ports.map((p, i) => (
                <Badge key={i} variant="info" className="font-mono text-[10px]">{p}</Badge>
              ))}
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted-foreground">
                  {showAllSrcPorts ? `Showing all ${threat.source_ports.length} ports` : `Showing first 10 of ${threat.source_ports.length}`}
                </span>
                <button
                  onClick={() => setShowAllSrcPorts(!showAllSrcPorts)}
                  className="text-[10px] text-cyber-cyan hover:underline flex items-center gap-1"
                >
                  {showAllSrcPorts ? <><ChevronUp className="h-3 w-3" />Collapse</> : <><ChevronDown className="h-3 w-3" />Expand all</>}
                </button>
              </div>
              <div className="flex flex-wrap gap-1">
                {(showAllSrcPorts ? threat.source_ports : srcPortsPreview).map((p, i) => (
                  <span key={i} className="font-mono text-[10px] text-muted-foreground bg-muted/30 rounded px-1.5 py-0.5">{p}</span>
                ))}
                {!showAllSrcPorts && (
                  <span className="text-[10px] text-muted-foreground/60">...and {threat.source_ports.length - 10} more</span>
                )}
              </div>
            </>
          )}
        </div>
        <p className="text-[10px] text-muted-foreground/50 mt-1">
          High source-port diversity ({threat.source_ports.length} unique ports across {threat.session_count} sessions) 
          is typical of automated scanning rather than interactive manual access.
        </p>
      </div>

      {/* Network summary */}
      <div className="rounded border border-border bg-muted/10 p-3">
        <h4 className="text-xs font-semibold mb-2">Network Activity Summary</h4>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 text-xs">
          <div>
            <div className="text-[10px] text-muted-foreground">Unique Source IP</div>
            <div className="font-mono font-bold text-cyber-cyan">{threat.ip_address}</div>
          </div>
          <div>
            <div className="text-[10px] text-muted-foreground">Protocol(s)</div>
            <div className="font-mono font-bold">{threat.protocols.join(", ") || "N/A"}</div>
          </div>
          <div>
            <div className="text-[10px] text-muted-foreground">Unique Source Ports</div>
            <div className="font-bold">{threat.source_ports.length}</div>
          </div>
          <div>
            <div className="text-[10px] text-muted-foreground">Unique Dst Ports</div>
            <div className="font-bold">{threat.ports.length}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   TAB 7 — EVIDENCE (technique evidence + related activity + export)
   ═══════════════════════════════════════════════════════════════ */
function EvidenceTab({ threat }: { threat: Threat }) {
  function handleFullExport() {
    const content = JSON.stringify(threat, null, 2);
    const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `threat-full-evidence-${threat.ip_address ?? threat.id}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function handleCSVExport() {
    const headers = ["timestamp", "event_id", "event_type", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "request", "mitre_technique"];
    const rows = threat.observations.map((o) =>
      headers.map((h) => {
        const val = o[h as keyof HoneypotObservation];
        if (val == null) return "";
        return `"${String(val).replace(/"/g, '""')}"`;
      }).join(","),
    );
    const csv = [headers.join(","), ...rows].join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `threat-events-${threat.ip_address ?? threat.id}.csv`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <div className="space-y-4">
      {/* Export actions */}
      <div className="flex gap-2 flex-wrap">
        <Button size="sm" variant="cyber" onClick={handleFullExport}>
          <Download className="mr-1 h-3.5 w-3.5" />Export Full Evidence (JSON)
        </Button>
        <Button size="sm" variant="outline" onClick={handleCSVExport}>
          <Download className="mr-1 h-3.5 w-3.5" />Export Events (CSV)
        </Button>
        <Button size="sm" variant="outline">
          <User className="mr-1 h-3.5 w-3.5" />Assign Analyst
        </Button>
        <Button size="sm" variant="outline">
          <Shield className="mr-1 h-3.5 w-3.5" />Mark Contained
        </Button>
      </div>

      {/* Technique evidence */}
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
          Technique Evidence ({threat.technique_evidence.length})
        </h4>
        {threat.technique_evidence.length > 0 ? (
          <div className="space-y-1.5">
            {threat.technique_evidence.map((evidence, index) => (
              <div key={`${evidence.technique_id}-${evidence.timestamp}-${index}`} className="rounded border border-border bg-muted/10 p-2.5 text-xs">
                <div className="flex items-center gap-2 mb-1">
                  <Badge variant="violet" className="font-mono text-[10px]">{evidence.technique_id}</Badge>
                  <span className="text-muted-foreground">{evidence.event_type ?? evidence.event_id}</span>
                  <span className="text-muted-foreground ml-auto">{formatDateTime(evidence.timestamp)}</span>
                </div>
                {evidence.request && (
                  <code className="block break-all rounded bg-black/30 p-2 font-mono text-[11px] text-emerald-300 mt-1">
                    Triggering evidence: {evidence.request}
                  </code>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground rounded border border-border bg-muted/10 p-3 text-center">
            No technique-specific evidence correlated. Events were limited to connection-level activity.
          </p>
        )}
      </div>

      {/* Related Activity */}
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
          Related Activity ({threat.related_activity.length})
        </h4>
        {threat.related_activity.length > 0 ? (
          <div className="space-y-1.5">
            {threat.related_activity.map((item, index) => (
              <div key={`${item.kind}-${item.actor_id}-${index}`} className="rounded border border-border bg-muted/10 p-2.5 text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-cyber-cyan">{item.actor_ip}</span>
                  <span className="text-muted-foreground">{item.detail}</span>
                </div>
                {item.kind === "same_source_ip_sessions" && item.session_ids && (
                  <div className="mt-1 text-[10px] text-muted-foreground/60">
                    Links to {item.session_ids.length} session{item.session_ids.length > 1 ? "s" : ""}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground rounded border border-border bg-muted/10 p-3 text-center">
            No matching observed command, technique, protocol/port, or repeat session found.
          </p>
        )}
      </div>

      {/* Evidence summary */}
      <div className="rounded border border-border bg-muted/10 p-3 text-xs space-y-1.5">
        <h4 className="font-semibold text-sm">Evidence Summary</h4>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
          <div><span className="text-muted-foreground">Total Events:</span> <span className="font-bold">{threat.event_count}</span></div>
          <div><span className="text-muted-foreground">Sessions:</span> <span className="font-bold">{threat.session_count}</span></div>
          <div><span className="text-muted-foreground">Commands:</span> <span className="font-bold">{threat.commands.length}</span></div>
          <div><span className="text-muted-foreground">Techniques Mapped:</span> <span className="font-bold">{threat.techniques.length}</span></div>
          <div><span className="text-muted-foreground">Related Links:</span> <span className="font-bold">{threat.related_activity.length}</span></div>
          <div><span className="text-muted-foreground">Return Activity:</span> <span className="font-bold">{threat.return_activity ? "Yes" : "No"}</span></div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   SHARED COMPONENTS
   ═══════════════════════════════════════════════════════════════ */

function KpiMini({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number; color: string }) {
  const colorMap: Record<string, string> = {
    cyan: "text-cyber-cyan border-cyber-cyan/30 bg-cyber-cyan/5",
    blue: "text-blue-400 border-blue-400/30 bg-blue-400/5",
    yellow: "text-yellow-400 border-yellow-400/30 bg-yellow-400/5",
    red: "text-red-400 border-red-400/30 bg-red-400/5",
  };

  return (
    <div className={`rounded-lg border p-3 ${colorMap[color] ?? colorMap.cyan}`}>
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        {icon}
        <span>{label}</span>
      </div>
      <div className="mt-1 text-2xl font-bold">{value.toLocaleString()}</div>
    </div>
  );
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return "Not available";
  if (seconds < 60) return `${seconds} sec`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.round(seconds % 60);
  if (minutes < 60) return `${minutes} min ${remainingSeconds} sec`;
  return `${Math.floor(minutes / 60)} hr ${minutes % 60} min`;
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="font-medium text-sm">{value}</div>
    </div>
  );
}
