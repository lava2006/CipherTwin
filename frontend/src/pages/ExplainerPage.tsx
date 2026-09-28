import { Bot, CheckCircle2, Lightbulb, Sparkles } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { RiskDecision } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { RiskBadge } from "@/components/RiskBadge";
import { formatDateTime, riskColor } from "@/lib/utils";

export default function ExplainerPage() {
  const decisions = usePolling<{ items: RiskDecision[]; total: number }>(
    "/risk/decisions?page=1&page_size=20",
    5000,
  );
  const improvements = usePolling<any[]>("/optimization/history?limit=10", 10000);

  const items = decisions.data?.items ?? [];

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Explainability Engine"
        description="Every Zero Trust decision and every optimization is paired with a human-readable narrative."
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Bot className="h-4 w-4 text-cyber-cyan" />Recent Decision Reasons</CardTitle>
         </CardHeader>
          <CardContent className="space-y-3">
            {decisions.loading && !items.length ? (
              Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24 w-full" />)
            ) : (
              items.slice(0, 6).map((d) => (
                <div key={d.id} className="rounded-lg border border-border bg-card/40 p-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span className="font-mono">{formatDateTime(d.timestamp)}</span>
                    <RiskBadge decision={d.decision} />
                    <span className="ml-auto">{`user ${d.user_id}`}</span>
                 </div>
                  <div className="mt-1 flex items-center gap-2">
                    <div className="text-2xl font-bold" style={{ color: riskColor(d.risk_score) }}>
                      {d.risk_score.toFixed(0)}
                   </div>
                    <div className="text-xs text-muted-foreground">confidence {d.confidence.toFixed(0)}%</div>
                 </div>
                  <Progress value={d.risk_score} className="mt-1" />
                  <p className="mt-2 text-sm">{`${d.summary}`}</p>
                  <div className="mt-2 grid grid-cols-2 gap-2 text-xs md:grid-cols-3">
                    {d.factors.map((f) => (
                      <div key={f.name} className="rounded bg-muted/30 p-2">
                        <div className="text-muted-foreground">{`${f.name}`}</div>
                        <div className="font-mono">{f.score.toFixed(0)} ({f.contribution.toFixed(1)})</div>
                     </div>
                    ))}
                 </div>
               </div>
              ))
            )}
         </CardContent>
       </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Sparkles className="h-4 w-4 text-cyber-cyan" />Optimization Narratives</CardTitle>
         </CardHeader>
          <CardContent className="space-y-3">
            {(improvements.data ?? []).map((h) => (
              <div key={h.id} className="rounded-lg border border-border bg-card/40 p-3">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span className="font-mono">{formatDateTime(h.timestamp)}</span>
                  <Badge variant="info">{`${h.algorithm}`}</Badge>
               </div>
                <div className="mt-2 flex items-center gap-2">
                  <Lightbulb className="h-4 w-4 text-amber-300" />
                  <span className="text-sm">{`${h.summary}`}</span>
               </div>
                <div className="mt-2 flex items-center gap-3 text-xs">
                  <span className="font-mono text-muted-foreground line-through">{h.before_score?.toFixed(2)}</span>
                  <span className="font-mono text-emerald-300">{h.after_score?.toFixed(2)}</span>
                  <span className="ml-auto text-muted-foreground">{h.iterations} iter â€¢ {h.duration_ms} ms</span>
               </div>
                <div className="mt-2 space-y-1">
                  {(h.changes ?? []).slice(0, 3).map((c: any, i: number) => (
                    <div key={i} className="flex items-center gap-1 text-xs">
                      <CheckCircle2 className="h-3 w-3 text-cyber-cyan" />
                      <span className="text-muted-foreground">{`${c.policy}`}</span>
                      <span className="font-mono">{c.weight_before.toFixed(2)} â†’ {c.weight_after.toFixed(2)}</span>
                   </div>
                  ))}
               </div>
             </div>
            ))}
            {(!improvements.data || improvements.data.length === 0) && (
              <p className="text-sm text-muted-foreground">No optimization narratives yet</p>
            )}
         </CardContent>
       </Card>
     </div>
   </div>
  );
}
