import { useState } from "react";
import { Crosshair, Radar, ShieldAlert, User } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { Threat } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/utils";

export default function ThreatsPage() {
  const threats = usePolling<Threat[]>("/threats", 6000);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const list = threats.data ?? [];
  const active = list.find((t) => t.id === selectedId) || list[0];

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
    <div className="space-y-6">
      <SectionHeader
        title="Threat Intelligence"
        description="Observed Cowrie sources and event evidence. External intelligence is shown only when a provider is configured."
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Radar className="h-4 w-4 text-cyber-cyan" />Actors</CardTitle>
      </CardHeader>
          <CardContent className="space-y-2">
            {threats.loading && !list.length ? (
              Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)
            ) : (
              list.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setSelectedId(t.id)}
                  className={`w-full text-left rounded-lg border p-3 transition-colors ${selectedId === t.id || (!selectedId && t === list[0]) ? "border-cyber-cyan/40 bg-cyber-cyan/10" : "border-border bg-card/40 hover:bg-muted/30"}`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Crosshair className="h-4 w-4 text-cyber-cyan" />
                      <div>
                        <div className="text-sm font-semibold">{`${t.actor_name}`}</div>
                        <div className="text-xs text-muted-foreground">{`${t.username ?? "Username not recorded"}`}</div>
                </div>
              </div>
                    <div className="flex flex-col items-end gap-1">
                      <Badge variant="info">Observed</Badge>
                      <Badge
                        variant={t.severity.label === "Elevated activity" ? "danger" : t.severity.label === "Active probing" ? "warning" : "success"}
                        title={t.severity.reason}
                      >
                        {t.severity.label}
                      </Badge>
                    </div>
            </div>
                  <div className="mt-2 flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">{`${t.ip_address ?? "n/a"}`}</span>
                    <span className="font-bold text-cyber-cyan">{`${t.event_count} events`}</span>
            </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {t.techniques.map((technique) => (
                      <Badge key={technique} variant="violet" className="px-1.5 py-0 font-mono text-[10px]">{technique}</Badge>
                    ))}
                  </div>
          </button>
              ))
            )}
            {list.length === 0 && (
              <p className="text-sm text-muted-foreground">No threats correlated yet</p>
            )}
      </CardContent>
    </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><ShieldAlert className="h-4 w-4 text-cyber-cyan" />Threat Detail</CardTitle>
      </CardHeader>
          <CardContent>
            {active ? (
              <div className="space-y-5">
                <div className="flex items-center gap-4">
                  <div className="flex h-14 w-14 items-center justify-center rounded-lg bg-cyber-cyan/20 text-cyber-cyan">
                    <Crosshair className="h-6 w-6" />
          </div>
                  <div>
                    <div className="text-xl font-bold">{`${active.actor_name}`}</div>
                    <div className="text-xs text-muted-foreground">{`${active.description}`}</div>
        </div>
                  <div className="ml-auto flex items-center gap-2">
                    <Badge
                      variant={active.severity.label === "Elevated activity" ? "danger" : active.severity.label === "Active probing" ? "warning" : "success"}
                      title={active.severity.reason}
                    >
                      {active.severity.label}
                    </Badge>
                    <Badge variant="info">Observed by honeypot</Badge>
          </div>
        </div>

                <div className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
                  <Field label="Username" value={`${active.username ?? "N/A"}`} />
                  <Field label="Source IP" value={`${active.ip_address ?? "N/A"}`} />
                  <Field label="Observed Events" value={`${active.event_count}`} />
                  <Field label="First Seen" value={`${formatDateTime(active.first_seen)}`} />
                  <Field label="Last Seen" value={`${formatDateTime(active.last_seen)}`} />
                  <Field label="Observed Span" value={formatDuration(active.duration_seconds)} />
                  <Field label="Cowrie Sessions" value={`${active.session_count}${active.return_activity ? " · return activity" : ""}`} />
                  <Field label="Protocol / Source → Destination Port" value={`${active.protocols.join(", ") || "Not recorded"} / ${active.source_ports.join(", ") || "Not recorded"} → ${active.ports.join(", ") || "Not recorded"}`} />
        </div>

                <div className="text-xs text-muted-foreground">
                  Classification rule: {active.severity.reason}
                  {active.return_activity && " Return activity means distinct Cowrie session IDs were observed for this source IP."}
                </div>

                <div>
                  <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">Observed Cowrie Sessions</h3>
                  <div className="space-y-1">
                    {active.sessions.map((session) => (
                      <div id={`cowrie-session-${session.id}`} key={session.id} className="rounded border border-border bg-muted/20 p-2 text-xs">
                        <div className="font-mono">Session {session.session_id ?? session.id}</div>
                        <div className="text-muted-foreground">
                          {formatDateTime(session.first_seen)} to {formatDateTime(session.last_seen)} · {session.protocols.join(", ") || "protocol not recorded"}
                          {session.ports.length ? ` / destination ports ${session.ports.join(", ")}` : " / destination port not recorded"}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-md border border-border bg-muted/20 p-3 text-sm">
                  <div className="font-semibold">External Intelligence: Not Available</div>
                  <div className="mt-1 text-xs text-muted-foreground">No external provider is configured. This profile contains observed honeypot evidence only.</div>
                </div>

                <div>
                  <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">Observed Honeypot Evidence</h3>
                  <div className="space-y-2">
                    {active.observations.map((event, index) => (
                      <div key={`${event.event_id}-${event.timestamp}-${index}`} className="rounded-md border border-border bg-muted/20 p-3 text-xs">
                        <div className="flex flex-wrap justify-between gap-2">
                          <span className="font-semibold">{event.event_type} ({event.event_id})</span>
                          <span className="text-muted-foreground">{formatDateTime(event.timestamp)}</span>
                        </div>
                        <div className="mt-1 text-muted-foreground">
                          {event.src_ip}{event.src_port != null ? `:${event.src_port}` : ""}{event.dst_ip ? ` to ${event.dst_ip}` : ""}
                          {event.protocol ? ` | ${event.protocol}` : ""}
                          {event.dst_port != null ? `:${event.dst_port}` : ""}
                        </div>
                        {event.request && <code className="mt-1 block break-all">{event.request}</code>}
                      </div>
                    ))}
                    {!active.observations.length && <p className="text-xs text-muted-foreground">No event details recorded.</p>}
                  </div>
                </div>

                <div>
                  <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">Technique Mapping From Observed Events</h3>
                  {active.techniques.length ? (
                    <div className="space-y-2">
                      <div className="flex flex-wrap gap-2">
                        {active.techniques.map((tid) => (
                          <Badge key={tid} variant="violet" className="font-mono">{tid}</Badge>
                        ))}
                      </div>
                      <div className="space-y-1">
                        {active.technique_evidence.map((evidence, index) => (
                          <div key={`${evidence.technique_id}-${evidence.timestamp}-${index}`} className="rounded border border-border bg-muted/20 p-2 text-xs">
                            <span className="font-mono text-violet-300">{evidence.technique_id}</span>
                            <span className="text-muted-foreground"> · {evidence.event_type ?? evidence.event_id} · {formatDateTime(evidence.timestamp)}</span>
                            {evidence.request && <code className="mt-1 block break-all">Triggering evidence: {evidence.request}</code>}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">No techniques correlated</p>
                  )}
        </div>

                <div>
                  <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">Observed Commands</h3>
                  <div className="space-y-1 rounded-lg border border-border bg-muted/30 p-3 font-mono text-xs">
                    {active.commands.length ? (
                      active.commands.map((c, i) => (
                        <div key={i} className="text-emerald-300">{`$ ${c}`}</div>
                      ))
                    ) : (
                      <p className="text-muted-foreground">No commands recorded</p>
                    )}
        </div>
        </div>

                <div>
                  <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">Tactics Breakdown</h3>
                  {active.tactics ? (
                    <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                      {Object.entries(active.tactics).map(([tactic, techs]) => (
                        <div key={tactic} className="rounded-md border border-border bg-card/40 p-3">
                          <div className="text-xs font-semibold text-cyber-cyan">{`${tactic}`}</div>
                          <div className="mt-1 space-y-1 text-xs">
                            {(techs as string[]).map((t, i) => (
                              <div key={i} className="font-mono text-muted-foreground">{`${t}`}</div>
                            ))}
              </div>
            </div>
                      ))}
          </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">Loading tactics</p>
                  )}
        </div>

                <div>
                  <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">Related Activity</h3>
                  {active.related_activity.length ? (
                    <div className="space-y-1">
                      {active.related_activity.map((item, index) => (
                        <div key={`${item.kind}-${item.actor_id}-${index}`} className="rounded border border-border bg-muted/20 p-2 text-xs">
                          {item.kind === "same_source_ip_sessions" ? (
                            <>
                              <span className="font-mono text-cyber-cyan">{item.actor_ip}</span>
                              <span className="ml-2 text-muted-foreground">{item.detail}</span>
                              <div className="mt-1 flex flex-wrap gap-2">
                                {item.session_ids?.map((sessionId) => (
                                  <a key={sessionId} className="text-cyan-300 underline" href={`#cowrie-session-${sessionId}`}>
                                    Open session {sessionId}
                                  </a>
                                ))}
                              </div>
                            </>
                          ) : (
                            <button className="text-left" onClick={() => setSelectedId(item.actor_id)} title={`Open observed actor ${item.actor_ip}`}>
                              <span className="font-mono text-cyber-cyan">{item.actor_ip}</span>
                              <span className="ml-2 text-muted-foreground">{item.detail}</span>
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">No matching observed command, technique, protocol/port, or repeat session found.</p>
                  )}
                </div>

                <div className="flex gap-2">
                  <Button size="sm" variant="cyber"><User className="mr-1 h-3.5 w-3.5" />Assign Analyst</Button>
                  <Button size="sm" variant="outline">Mark Contained</Button>
                  <Button size="sm" variant="outline" onClick={handleExport}>Export IOC</Button>
        </div>
      </div>
            ) : (
              <p className="text-sm text-muted-foreground">Select a threat actor to inspect details</p>
            )}
      </CardContent>
    </Card>
  </div>
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
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{`${label}`}</div>
      <div className="font-medium">{`${value}`}</div>
</div>
  );
}
