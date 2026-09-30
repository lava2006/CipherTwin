import { useState } from "react";
import { Eye, Fingerprint, Plus, Shield, Terminal, Webhook, Cpu, CheckCircle2 } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { DecoySession, HoneypotObservation, Honeytoken } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/Toaster";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";

const ICONS: Record<string, JSX.Element> = {
  ssh: <Terminal className="h-4 w-4" />,
  database: <Fingerprint className="h-4 w-4" />,
  web: <Webhook className="h-4 w-4" />,
  admin_panel: <Eye className="h-4 w-4" />,
  api: <Cpu className="h-4 w-4" />,
};

interface FidelityStatus {
  mode: string;
  status: string;
  cowrie_status: string;
  log_status: string;
  log_file: string | null;
  total_events: number;
  last_event: string | null;
  cowrie_enabled: boolean;
  total_sessions: number;
  fidelity_breakdown: {
    low: number;
    medium: number;
    high: number;
  };
}

export default function DeceptionPage() {
  const sessions = usePolling<DecoySession[]>("/deception/sessions", 5000);
  const tokens = usePolling<Honeytoken[]>("/deception/honeytokens", 6000);
  const fidelityInfo = usePolling<FidelityStatus>("/deception/fidelity/status", 6000);
  const [active, setActive] = useState<DecoySession | null>(null);
  const { toast } = useToast();

  async function reseed() {
    try {
      await api.post("/deception/seed");
      toast({
        title: "Honeytokens Planted",
        description: "Credentials, API keys, decoy files, URLs, cookies, and DB records deployed.",
        variant: "success",
      });
    } catch {
      toast({ title: "Seed failed", variant: "error" });
    }
  }

  async function trigger(id: number) {
    try {
      const res = await api.post(`/deception/trigger/${id}`);
      toast({
        title: "Critical Honeytoken Alert Triggered",
        description: `Threat escalated to risk 95. Attacker automatically trapped in high-fidelity decoy.`,
        variant: "error",
      });
    } catch {
      toast({ title: "Trigger failed", variant: "error" });
    }
  }

  const list = sessions.data ?? [];
  const tokenList = tokens.data ?? [];
  const fed = fidelityInfo.data;

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Adaptive Deception Engine"
        description="Cowrie honeypot sessions and observed interaction events, paired with honeytoken controls."
        actions={
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="font-mono text-xs">
              Backend: {fed?.mode ?? "UNAVAILABLE"}
            </Badge>
            <Button variant="cyber" size="sm" onClick={reseed}>
              <Plus className="mr-1 h-3.5 w-3.5" /> Plant Honeytokens
            </Button>
          </div>
        }
      />

      {/* Fidelity & Engine Posture Bar */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Card className="border-border bg-card/40">
          <CardContent className="p-3">
            <div className="text-[10px] uppercase text-muted-foreground">Mode</div>
            <div className="text-base font-bold text-cyber-cyan">{fed?.mode ?? "UNAVAILABLE"}</div>
            <div className="text-[11px] text-muted-foreground">
              {fed?.cowrie_status ?? "OFFLINE"} | Log {fed?.log_status ?? "UNAVAILABLE"}
            </div>
            <div className="text-[11px] text-muted-foreground">{fed?.total_events ?? 0} events | Last: {fed?.last_event ? formatDateTime(fed.last_event) : "None"}</div>
          </CardContent>
        </Card>
        <Card className="border-border bg-card/40">
          <CardContent className="p-3">
            <div className="text-[10px] uppercase text-muted-foreground">High Fidelity Traps</div>
            <div className="text-base font-bold text-rose-400">{fed?.fidelity_breakdown.high ?? 0}</div>
            <div className="text-[11px] text-muted-foreground">Deep interactive capture</div>
          </CardContent>
        </Card>
        <Card className="border-border bg-card/40">
          <CardContent className="p-3">
            <div className="text-[10px] uppercase text-muted-foreground">Medium Fidelity</div>
            <div className="text-base font-bold text-violet-400">{fed?.fidelity_breakdown.medium ?? 0}</div>
            <div className="text-[11px] text-muted-foreground">Observed Cowrie sessions</div>
          </CardContent>
        </Card>
        <Card className="border-border bg-card/40">
          <CardContent className="p-3">
            <div className="text-[10px] uppercase text-muted-foreground">Low Fidelity</div>
            <div className="text-base font-bold text-slate-300">{fed?.fidelity_breakdown.low ?? 0}</div>
            <div className="text-[11px] text-muted-foreground">Banner & connection logging</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle>Observed Cowrie Sessions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {sessions.loading && !list.length ? (
              Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)
            ) : (
              list.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setActive(s)}
                  className={`w-full text-left rounded-lg border p-3 transition-colors ${
                    active?.id === s.id
                      ? "border-cyber-violet/40 bg-violet-500/10"
                      : "border-border bg-card/40 hover:bg-muted/30"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-md bg-violet-500/20 text-violet-300">
                      {ICONS[s.decoy_type] ?? <Eye className="h-4 w-4" />}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold capitalize">
                          {s.decoy_type.replace("_", " ")} Decoy
                        </span>
                        <Badge
                          variant={
                            s.fidelity === "HIGH"
                              ? "danger"
                              : s.fidelity === "LOW"
                              ? "outline"
                              : "violet"
                          }
                          className="text-[10px]"
                        >
                          {s.fidelity || "MEDIUM"} FIDELITY
                        </Badge>
                      </div>
                      <div className="truncate text-xs text-muted-foreground">
                        Protocol: {observedProtocol(s)} | Username: {s.actor ?? "Not recorded"} | Source IP: {s.source_ip ?? "Not recorded"} | {observedEvents(s).length} events
                      </div>
                    </div>
                    <Badge variant="violet">{formatDateTime(s.timestamp)}</Badge>
                  </div>
                </button>
              ))
            )}
            {list.length === 0 && (
              <p className="text-sm text-muted-foreground">
                No decoy sessions yet. Risky traffic will be redirected here automatically.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Session Detail & Signals</CardTitle>
          </CardHeader>
          <CardContent>
            {active ? (
              <div className="space-y-4 text-sm">
                <div className="rounded-md border border-violet-500/30 bg-violet-500/5 p-3">
                  <div className="text-xs uppercase tracking-wider text-violet-300">
                    Adaptive Trigger Reason
                  </div>
                  <div className="text-xs mt-1">{active.reason || active.notes}</div>
                  <div className="mt-2 flex items-center gap-2 text-[11px] text-muted-foreground">
                    <span>Fidelity: {active.fidelity || "Not classified"}</span>
                    {active.confidence != null && <><span>|</span><span>Confidence: {(active.confidence * 100).toFixed(0)}%</span></>}
                  </div>
                </div>
                {active.persona && (
                  <div>
                    <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">
                      Active Honeypot Persona
                    </div>
                    <div className="rounded-md bg-muted/30 p-2 font-mono text-xs text-cyber-cyan">
                      {active.persona}
                    </div>
                  </div>
                )}
                {active.banner && (
                  <div>
                    <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">
                      Emulated Service Banner
                    </div>
                    <div className="rounded-md bg-muted/30 p-2 font-mono text-xs text-amber-300">
                      {active.banner}
                    </div>
                  </div>
                )}
                <div>
                  <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">
                    Credentials trapped
                  </div>
                  <div className="rounded-md bg-muted/30 p-2 font-mono text-xs">
                    {active.credentials_used ?? "None recorded"}
                  </div>
                </div>
                <div>
                  <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">
                    Activity timeline
                  </div>
                  <ul className="space-y-1 text-xs">
                    {(active.activity ?? []).map((event, i) => (
                      typeof event === "string" ? (
                        <li key={i} className="rounded bg-muted/30 px-2 py-1">{event}</li>
                      ) : (
                        <li key={i} className="rounded bg-muted/30 px-2 py-2">
                          <div>{formatDateTime(event.timestamp)} | {event.event_type} ({event.event_id})</div>
                          <div className="text-muted-foreground">
                            {event.src_ip}{event.src_port != null ? `:${event.src_port}` : ""}{event.dst_ip ? ` to ${event.dst_ip}` : ""}
                            {event.protocol ? ` | ${event.protocol}` : ""}
                            {event.dst_port != null ? `:${event.dst_port}` : ""}
                          </div>
                          {event.request && <code className="mt-1 block break-all">{event.request}</code>}
                        </li>
                      )
                    ))}
                  </ul>
                </div>
                <div>
                  <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">
                    Commands recorded
                  </div>
                  <ul className="space-y-1 font-mono text-xs">
                    {(active.commands ?? []).map((c, i) => (
                      <li key={i} className="rounded bg-muted/30 px-2 py-1 text-emerald-300">
                        $ {c}
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">
                    Pages probed
                  </div>
                  <ul className="space-y-1 font-mono text-xs">
                    {(active.pages ?? []).map((p, i) => (
                      <li key={i} className="rounded bg-muted/30 px-2 py-1 text-cyan-300">
                        GET {p}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                Select a decoy session to inspect what the attacker did.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle>Honeytokens (Credentials, Keys, Files, URLs, Cookies, DB Records)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                <tr className="border-b border-border">
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Label</th>
                  <th className="px-3 py-2">Value</th>
                  <th className="px-3 py-2">Planted on</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Action</th>
                </tr>
              </thead>
              <tbody>
                {tokenList.map((t) => (
                  <tr key={t.id} className="border-b border-border/40 hover:bg-muted/20">
                    <td className="px-3 py-2 capitalize font-mono text-xs text-cyber-cyan">
                      {t.token_type}
                    </td>
                    <td className="px-3 py-2 font-medium">{t.label}</td>
                    <td className="px-3 py-2 font-mono text-xs">{t.value}</td>
                    <td className="px-3 py-2">{t.planted_on ?? "N/A"}</td>
                    <td className="px-3 py-2">
                      <Badge variant={t.triggered ? "danger" : "outline"}>
                        {t.triggered ? "Triggered" : "Armed"}
                      </Badge>
                    </td>
                    <td className="px-3 py-2">
                      <Button size="sm" variant="outline" onClick={() => trigger(t.id)}>
                        Simulate trigger
                      </Button>
                    </td>
                  </tr>
                ))}
                {tokenList.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-3 py-6 text-center text-sm text-muted-foreground">
                      No honeytokens yet. Click Plant Honeytokens to distribute.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function observedEvents(session: DecoySession): HoneypotObservation[] {
  return session.activity.filter((event): event is HoneypotObservation => typeof event !== "string");
}

function observedProtocol(session: DecoySession): string {
  return observedEvents(session).find((event) => event.protocol)?.protocol ?? "Not recorded";
}
