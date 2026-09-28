import { useState } from "react";
import { History, Save, ShieldCheck } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { Policy } from "@/lib/types";
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

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Policy History & Management"
        description="Inspect, tune, and version-control Zero Trust policies. Every change is audit-logged."
      />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-cyber-cyan" />Active Policies</CardTitle>
       </CardHeader>
        <CardContent>
          {policies.loading && !policies.data ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}
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
                          <div className="text-sm font-semibold">{`${p.name}`}</div>
                          <Badge variant="info">{`priority ${p.priority}`}</Badge>
                          <Badge variant={p.enabled ? "success" : "outline"}>{p.enabled ? "enabled" : "disabled"}</Badge>
                       </div>
                        <div className="mt-1 text-xs text-muted-foreground">{`${p.description}`}</div>
                        <div className="mt-1 font-mono text-[11px] text-cyber-cyan">{`${p.rule}`}</div>
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
                                [p.id]: { weight: Number(ev.target.value), priority: e?.priority ?? p.priority, enabled: e?.enabled ?? p.enabled },
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

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2"><History className="h-4 w-4 text-cyber-cyan" />Optimization History</CardTitle>
       </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {(history.data ?? []).map((h) => (
              <div key={h.id} className="flex flex-col gap-2 rounded-md border border-border bg-card/40 p-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <div className="text-xs text-muted-foreground">{`${formatDateTime(h.timestamp)} â€¢ ${h.algorithm}`}</div>
                  <div className="mt-0.5 text-sm">{`${h.summary}`}</div>
               </div>
                <div className="flex items-center gap-3 text-xs">
                  <span className="font-mono text-muted-foreground line-through">{h.before_score?.toFixed(2)}</span>
                  <span className="font-mono text-emerald-300">{h.after_score?.toFixed(2)}</span>
                  <Badge variant="success">Î” {(h.before_score - h.after_score).toFixed(2)}</Badge>
                  <span className="text-muted-foreground">{h.iterations} iter â€¢ {h.duration_ms} ms</span>
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
