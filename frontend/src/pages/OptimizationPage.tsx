import { useState } from "react";
import { Atom, Gauge, Sparkles, Target, TrendingDown } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/components/Toaster";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";

interface OptimizationResult {
  before_score: number;
  after_score: number;
  before_fp: number;
  after_fp: number;
  before_fn: number;
  after_fn: number;
  iterations: number;
  duration_ms: number;
  changes: { policy: string; weight_before: number; weight_after: number; delta: number }[];
}

export default function OptimizationPage() {
  const state = usePolling<any>("/optimization/state", 10000);
  const history = usePolling<any[]>("/optimization/history?limit=20", 10000);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<OptimizationResult | null>(null);
  const { toast } = useToast();

  async function runOptimization() {
    setRunning(true);
    setProgress(0);
    setResult(null);
    // simulate progress
    const interval = setInterval(() => {
      setProgress((p) => Math.min(100, p + 6 + Math.random() * 4));
    }, 90);
    try {
      const res = await api.post<OptimizationResult>("/optimization/run", { layers: 3, iterations: 60 });
      setResult(res.data);
      toast({ title: "Optimization complete", description: `Score ${res.data.before_score} to ${res.data.after_score}.`, variant: "success" });
    } catch (e) {
      toast({ title: "Optimization failed", variant: "error" });
    } finally {
      clearInterval(interval);
      setProgress(100);
      setTimeout(() => setRunning(false), 600);
    }
  }

  const stats = state.data;

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Quantum Policy Optimization"
        description="Simulated QAOA rebalances Zero Trust policies every run, reducing false positives and false negatives."
        actions={
          <Button variant="cyber" onClick={runOptimization} disabled={running}>
            <Atom className="mr-2 h-4 w-4" />
            {running ? "Optimizing..." : "Run QAOA Optimization"}
     </Button>
        }
      />

      {/* Live progress */}
      <Card className="border-cyber-cyan/30">
        <CardContent className="space-y-3 p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-cyber-cyan" />
              <span className="text-sm font-semibold">QAOA Pipeline</span>
              {running && <Badge variant="info">Running</Badge>}
           </div>
            <span className="text-xs text-muted-foreground">{progress.toFixed(0)}%</span>
         </div>
          <Progress value={progress} />
          <div className="grid grid-cols-2 gap-3 text-xs text-muted-foreground md:grid-cols-4">
            <span>p-layers: 3</span>
            <span>qubits: 8 (simulated</span>
            <span>backend: numpy.linalg</span>
            <span>noise model: depolarizing-1%</span>
         </div>
       </CardContent>
     </Card>

      {result && (
        <Card className="border-emerald-500/40">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-emerald-300">
              <Target className="h-5 w-5" />Latest Result
           </CardTitle>
         </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Metric label="Cost score" before={result.before_score} after={result.after_score} lowerBetter />
            <Metric label="False positive rate" before={result.before_fp * 100} after={result.after_fp * 100} suffix="%" lowerBetter />
            <Metric label="False negative rate" before={result.before_fn * 100} after={result.after_fn * 100} suffix="%" lowerBetter />
            <Metric label="Iterations / Time" before={`${result.iterations} iter`} after={`${result.duration_ms} ms`} delta={false} />
         </CardContent>
          <CardContent>
            <div className="text-sm font-semibold">Policy Changes</div>
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="py-1.5">Policy</th>
                    <th className="py-1.5">Before</th>
                    <th className="py-1.5">After</th>
                    <th className="py-1.5">Delta</th>
                 </tr>
               </thead>
                <tbody>
                  {result.changes.map((c) => (
                    <tr key={c.policy} className="border-t border-border/40">
                      <td className="py-1.5">{`${c.policy}`}</td>
                      <td className="py-1.5 font-mono">{c.weight_before.toFixed(2)}</td>
                      <td className="py-1.5 font-mono">{c.weight_after.toFixed(2)}</td>
                      <td className={`py-1.5 font-mono ${c.delta >= 0 ? "text-emerald-300" : "text-red-300"}`}>
                        {c.delta >= 0 ? "+" : ""}{c.delta.toFixed(2)}
                     </td>
                   </tr>
                  ))}
               </tbody>
             </table>
           </div>
         </CardContent>
       </Card>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Gauge className="h-4 w-4 text-cyber-cyan" />Current Policy State</CardTitle>
         </CardHeader>
          <CardContent>
            {stats ? (
              <div className="space-y-3 text-sm">
                <div className="grid grid-cols-3 gap-3">
                  <Stat label="Avg FP" value={`${(stats.average_fp * 100).toFixed(2)}%`} />
                  <Stat label="Avg FN" value={`${(stats.average_fn * 100).toFixed(2)}%`} />
                  <Stat label="Avg weight" value={stats.average_weight.toFixed(2)} />
               </div>
                <div className="space-y-2">
                  {(stats.policies ?? []).slice(0, 6).map((p: any) => (
                    <div key={p.id} className="flex items-center gap-3 rounded-md border border-border bg-card/40 p-2">
                      <div className="flex-1">
                        <div className="text-sm font-medium">{`${p.name}`}</div>
                        <div className="text-xs text-muted-foreground">FP {(p.false_positive_rate * 100).toFixed(1)}% | FN {(p.false_negative_rate * 100).toFixed(1)}%</div>
                     </div>
                      <Badge variant={p.enabled ? "success" : "outline"}>{p.enabled ? "enabled" : "disabled"}</Badge>
                      <span className="font-mono text-xs text-cyber-cyan">{p.weight.toFixed(2)}</span>
                   </div>
                  ))}
               </div>
             </div>
            ) : (
              <p className="text-sm text-muted-foreground">Loading</p>
            )}
         </CardContent>
       </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><TrendingDown className="h-4 w-4 text-cyber-cyan" />Optimization History</CardTitle>
         </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {(history.data ?? []).map((h) => (
                <div key={h.id} className="rounded-md border border-border bg-card/40 p-3">
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>{formatDateTime(h.timestamp)}</span>
                    <Badge variant="info">{`${h.algorithm}`}</Badge>
                 </div>
                  <div className="mt-1 flex items-center gap-2 text-sm">
                    <span className="font-mono">{h.before_score?.toFixed(2)}</span>
                    <span className="text-xs text-muted-foreground">to</span>
                    <span className="font-mono text-emerald-300">{h.after_score?.toFixed(2)}</span>
                    <span className="ml-auto text-xs text-muted-foreground">Delta {(h.before_score - h.after_score).toFixed(2)} | {h.iterations} iter / {h.duration_ms} ms</span>
                 </div>
                  <div className="mt-1 text-xs text-muted-foreground">{`${h.summary}`}</div>
               </div>
              ))}
              {(!history.data || history.data.length === 0) && (
                <p className="text-sm text-muted-foreground">No optimization runs yet</p>
              )}
           </div>
         </CardContent>
       </Card>
     </div>
   </div>
  );
}

function Metric({ label, before, after, suffix = "", lowerBetter }: any) {
  const beforeNum = typeof before === "number" ? before : NaN;
  const afterNum = typeof after === "number" ? after : NaN;
  const improved = !isNaN(beforeNum) && !isNaN(afterNum) && lowerBetter ? afterNum < beforeNum : false;
  return (
    <div className="rounded-lg border border-border bg-card/40 p-3">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{`${label}`}</div>
      <div className="mt-1 flex items-baseline gap-2">
        <span className="text-xs text-muted-foreground line-through">{`${typeof before === "number" ? before.toFixed(2) : before}${suffix}`}</span>
        <span className={`text-lg font-bold ${improved ? "text-emerald-300" : ""}`}>{`${typeof after === "number" ? after.toFixed(2) : after}${suffix}`}</span>
     </div>
   </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/30 p-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{`${label}`}</div>
      <div className="text-sm font-semibold">{`${value}`}</div>
   </div>
  );
}
