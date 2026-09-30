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
                    <Badge variant="info">Observed</Badge>
            </div>
                  <div className="mt-2 flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">{`${t.ip_address ?? "n/a"}`}</span>
                    <span className="font-bold text-cyber-cyan">{`${t.event_count} events`}</span>
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
                    <Badge variant="info">Observed by honeypot</Badge>
          </div>
        </div>

                <div className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
                  <Field label="Username" value={`${active.username ?? "N/A"}`} />
                  <Field label="Source IP" value={`${active.ip_address ?? "N/A"}`} />
                  <Field label="Observed Events" value={`${active.event_count}`} />
                  <Field label="First Seen" value={`${formatDateTime(active.first_seen)}`} />
                  <Field label="Protocol / Source → Destination Port" value={`${active.protocols.join(", ") || "Not recorded"} / ${active.source_ports.join(", ") || "Not recorded"} → ${active.ports.join(", ") || "Not recorded"}`} />
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
                    <div className="flex flex-wrap gap-2">
                      {active.techniques.map((tid) => (
                        <Badge key={tid} variant="violet" className="font-mono">{`${tid}`}</Badge>
                      ))}
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

                <div className="flex gap-2">
                  <Button size="sm" variant="cyber"><User className="mr-1 h-3.5 w-3.5" />Assign Analyst</Button>
                  <Button size="sm" variant="outline">Mark Contained</Button>
                  <Button size="sm" variant="outline">Export IOC</Button>
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

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{`${label}`}</div>
      <div className="font-medium">{`${value}`}</div>
</div>
  );
}
