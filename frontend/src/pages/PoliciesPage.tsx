import { useState } from "react";
import { FlaskConical, History, Play, RotateCcw, Save, ShieldCheck } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { Policy, PolicySimulation } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useToast } from "@/components/Toaster";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";

export default function PoliciesPage() {
  const policies = usePolling<Policy[]>("/policies", 10000);
  const history = usePolling<any[]>("/optimization/history?limit=15", 10000);
  const { toast } = useToast();
  const [editing, setEditing] = useState<Record<number, { weight: number; priority: number; enabled: boolean }>>({});

  // Policy Simulation state
  const [simAllow, setSimAllow] = useState(30);
  const [simRestricted, setSimRestricted] = useState(60);
  const [simDeny, setSimDeny] = useState(100);
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<PolicySimulation | null>(null);

  function startEdit(p: Policy) {
    setEditing({ ...editing, [p.id]: { weight: p.weight, priority: p.priority, enabled: p.enabled } });
  }

  async function save(p: Policy) {
    const e = editing[p.id];
    if (!e) return;
    try {
      await api.patch(`/policies/${p.id}`, { weight: e.weight, priority: e.priority, enabled: e.enabled ? 1 : 0 });
      toast({ title: "Policy updated", variant: "success" });
    } catch {
      toast({ title: "Update failed", variant: "error" });
    }
  }

  async function runSimulation() {
    setSimulating(true);
    try {
      const res = await api.post<PolicySimulation>("/policies/simulate", {
        threshold_allow: simAllow,
        threshold_restricted: simRestricted,
        threshold_deny: simDeny,
        sample_size: 40,
      });
      setSimResult(res.data);
      toast({ title: "Simulation Complete", description: res.data.summary, variant: "success" });
    } catch {
      toast({ title: "Simulation Failed", variant: "error" });
    } finally {
      setSimulating(false);
    }
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Policy History & Management"
        description="Inspect, tune, version-control Zero Trust policies, and run safe 'What If?' simulations without touching production."
      />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyber-cyan" />
            Active Policies
          </CardTitle>
        </CardHeader>
        <CardContent>
          {policies.loading && !policies.data ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-16 w-full" />
              ))}
            </div>
          ) : (
            <div className="space-y-3">
              {(policies.data ?? []).map((p) => {
                const e = editing[p.id];
                return (
                  <div key={p.id} className="rounded-lg border border-border bg-card/40 p-4">
                    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <div className="text-sm font-semibold">{p.name}</div>
                          <Badge variant="info">priority {p.priority}</Badge>
                          <Badge variant={p.enabled ? "success" : "outline"}>
                            {p.enabled ? "enabled" : "disabled"}
                          </Badge>
                        </div>
                        <div className="mt-1 text-xs text-muted-foreground">{p.description}</div>
                        <div className="mt-1 font-mono text-[11px] text-cyber-cyan">{p.rule}</div>
                      </div>
                      <div className="flex items-center gap-3 text-xs">
                        <div>
                          <div className="text-muted-foreground">FP rate</div>
                          <div className="font-mono text-sm">{(p.false_positive_rate * 100).toFixed(2)}%</div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">FN rate</div>
                          <div className="font-mono text-sm">{(p.false_negative_rate * 100).toFixed(2)}%</div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">weight</div>
                          <Input
                            type="number"
                            step="0.05"
                            value={e?.weight ?? p.weight}
                            onChange={(ev) =>
                              setEditing({
                                ...editing,
                                [p.id]: {
                                  weight: Number(ev.target.value),
                                  priority: e?.priority ?? p.priority,
                                  enabled: e?.enabled ?? p.enabled,
                                },
                              })
                            }
                            className="h-8 w-20"
                          />
                        </div>
                        <Button size="sm" variant="cyber" onClick={() => save(p)} disabled={!e}>
                          <Save className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Safe 'What If?' Policy Simulation Card */}
      <Card className="border-cyber-cyan/30 bg-cyber-panel/60">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2">
            <FlaskConical className="h-4 w-4 text-cyber-cyan" />
            "What If?" Policy Simulation (Zero Production Risk)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-muted-foreground">
            Test how changing Zero Trust risk thresholds would impact real recent telemetry decisions without modifying live policy rules.
          </p>
          <div className="flex flex-wrap items-center gap-4 text-xs">
            <div>
              <span className="text-muted-foreground block mb-1">Allow Under (Risk &lt;)</span>
              <Input
                type="number"
                value={simAllow}
                onChange={(e) => setSimAllow(Number(e.target.value))}
                className="h-8 w-24 font-mono"
              />
            </div>
            <div>
              <span className="text-muted-foreground block mb-1">Restricted Under (&lt;)</span>
              <Input
                type="number"
                value={simRestricted}
                onChange={(e) => setSimRestricted(Number(e.target.value))}
                className="h-8 w-24 font-mono"
              />
            </div>
            <div>
              <span className="text-muted-foreground block mb-1">Deny Above (&ge;)</span>
              <Input
                type="number"
                value={simDeny}
                onChange={(e) => setSimDeny(Number(e.target.value))}
                className="h-8 w-24 font-mono"
              />
            </div>
            <div className="pt-5">
              <Button size="sm" variant="cyber" onClick={runSimulation} disabled={simulating} className="h-8 gap-1.5">
                <Play className="h-3.5 w-3.5" />
                {simulating ? "Simulating..." : "Run What-If Test"}
              </Button>
            </div>
          </div>

          {simResult && (
            <div className="mt-3 space-y-3 rounded-lg border border-border bg-card/60 p-4">
              <div className="flex flex-wrap items-center gap-3 text-xs">
                <Badge variant="outline">Evaluated: {simResult.total_evaluated}</Badge>
                <Badge variant="success">Allow: {simResult.allow_count}</Badge>
                <Badge variant="warning">Restricted: {simResult.restricted_count}</Badge>
                <Badge variant="violet">Deceive: {simResult.deceive_count}</Badge>
                <Badge variant="danger">Deny: {simResult.deny_count}</Badge>
                <Badge variant="info">Flipped Decisions: {simResult.changed_decisions}</Badge>
              </div>
              <p className="text-xs font-mono text-cyber-cyan">{simResult.summary}</p>
              {simResult.details.length > 0 && (
                <div className="max-h-48 overflow-y-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="border-b border-border/40 text-[10px] uppercase text-muted-foreground">
                      <tr>
                        <th className="py-1">Decision ID</th>
                        <th className="py-1">Risk Score</th>
                        <th className="py-1">Current Action</th>
                        <th className="py-1">Simulated Action</th>
                        <th className="py-1">Flipped?</th>
                      </tr>
                    </thead>
                    <tbody>
                      {simResult.details.map((d) => (
                        <tr key={d.id} className="border-b border-border/20">
                          <td className="py-1">#{d.id}</td>
                          <td className="py-1">{d.risk_score.toFixed(1)}</td>
                          <td className="py-1 uppercase text-muted-foreground">{d.current_decision}</td>
                          <td className="py-1 uppercase font-semibold text-cyber-cyan">{d.simulated_decision}</td>
                          <td className="py-1">{d.flipped ? <span className="text-amber-400">YES</span> : "no"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2">
            <History className="h-4 w-4 text-cyber-cyan" />
            Optimization History
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {(history.data ?? []).map((h) => (
              <div
                key={h.id}
                className="flex flex-col gap-2 rounded-md border border-border bg-card/40 p-3 md:flex-row md:items-center md:justify-between"
              >
                <div>
                  <div className="text-xs text-muted-foreground">
                    {formatDateTime(h.timestamp)} | {h.algorithm}
                  </div>
                  <div className="mt-0.5 text-sm">{h.summary}</div>
                </div>
                <div className="flex items-center gap-3 text-xs">
                  <span className="font-mono text-muted-foreground line-through">
                    {h.before_score?.toFixed(2)}
                  </span>
                  <span className="font-mono text-emerald-300">{h.after_score?.toFixed(2)}</span>
                  <Badge variant="success">Delta {(h.before_score - h.after_score).toFixed(2)}</Badge>
                  <span className="text-muted-foreground">
                    {h.iterations} iter | {h.duration_ms} ms
                  </span>
                </div>
              </div>
            ))}
            {(!history.data || history.data.length === 0) && (
              <p className="text-sm text-muted-foreground">No optimization history yet</p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
