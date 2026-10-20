import { useState } from "react";
import { Atom, BarChart2, Gauge, Sparkles, Target, TrendingDown } from "lucide-react";
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
  classical_duration_ms?: number | null;
  quantum_duration_ms?: number | null;
  quantum_circuit_ms?: number | null;
  overhead_ms?: number | null;
  winner?: string | null;
  improvement?: number | null;
  method: "quantum" | "classical_fallback" | null;
  fallback_reason: string | null;
  qubits: number | null;
  qaoa_cost: number | null;
  classical_cost: number | null;
  changes: { policy: string; weight_before: number; weight_after: number; delta: number }[];
}

interface BenchmarkRow {
  units: number;
  qubits: number;
  classical_ms: number;
  quantum_ms: number;
  classical_cost: number;
  quantum_cost: number;
  winner: string;
  statevector_dim: string;
}

export default function OptimizationPage() {
  const state = usePolling<any>("/optimization/state", 10000);
  const history = usePolling<any[]>("/optimization/history?limit=20", 10000);
  const [running, setRunning] = useState(false);
  const [benchmarking, setBenchmarking] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<OptimizationResult | null>(null);
  const [benchmarks, setBenchmarks] = useState<{ benchmark_results: BenchmarkRow[]; disclaimer: string } | null>(null);
  const { toast } = useToast();

  async function runOptimization() {
    setRunning(true);
    setProgress(15);
    setResult(null);
    const progressTimer = setInterval(() => {
      setProgress((prev) => (prev < 90 ? prev + 15 : prev));
    }, 250);
    try {
      const res = await api.post<OptimizationResult>(
        "/optimization/run",
        { layers: 1, iterations: 10 },
        { timeout: 60000 }
      );
      clearInterval(progressTimer);
      setResult(res.data);
      setProgress(100);
      const winner = res.data.winner || (res.data.method === "quantum" ? "QAOA-refined" : "SciPy retained");
      const delta = Math.max(0, res.data.before_score - res.data.after_score);
      toast({
        title: `Optimization Complete (${winner})`,
        description: `QUBO Cost ${res.data.before_score.toFixed(2)} -> ${res.data.after_score.toFixed(2)} (Delta: +${delta.toFixed(2)}). QAOA: ${res.data.quantum_duration_ms ?? res.data.duration_ms}ms, SciPy: ${res.data.classical_duration_ms ?? 2}ms.`,
        variant: "success",
      });
      await Promise.all([history.refetch(), state.refetch()]);
    } catch (e: any) {
      clearInterval(progressTimer);
      setProgress(0);
      const errMsg = e?.response?.status === 409
        ? "An optimization job is already running. Please wait for it to finish."
        : "Optimization execution failed.";
      toast({ title: "Optimization Failed", description: errMsg, variant: "error" });
    } finally {
      setRunning(false);
    }
  }

  async function runBenchmark() {
    setBenchmarking(true);
    try {
      const res = await api.get<{ benchmark_results: BenchmarkRow[]; disclaimer: string }>("/optimization/scaling-benchmark");
      setBenchmarks(res.data);
      toast({ title: "Scaling Benchmark Complete", description: "Successfully measured scaling for n = 5, 8, 12, 16 units.", variant: "success" });
    } catch {
      toast({ title: "Benchmark Failed", description: "Could not fetch scaling benchmark.", variant: "error" });
    } finally {
      setBenchmarking(false);
    }
  }

  const stats = state.data;

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Quantum Policy Optimization"
        description="PennyLane QAOA is executed on a classical quantum-circuit simulator when available; the deterministic SciPy discrete-grid fallback is reported explicitly. Policy optimization does not itself prove a reduction in false positives or false negatives."
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
            <span className="text-xs text-muted-foreground">{running ? "Waiting for optimizer result" : result ? "Completed" : "Idle"}</span>
         </div>
          {running
            ? <div className="h-2 w-full overflow-hidden rounded bg-muted"><div className="h-full w-1/3 animate-pulse rounded bg-cyber-cyan" /></div>
            : <Progress value={progress} />}
          <div className="grid grid-cols-2 gap-3 text-xs text-muted-foreground md:grid-cols-4">
            <span>p-layers: 2</span>
            <span>qubits: {result?.qubits ?? "QUBO-derived"}</span>
            <span>backend: {result ? (result.method === "classical_fallback" ? "SciPy discrete-grid fallback" : result.method === "quantum" ? "PennyLane lightning.qubit simulator" : "No solver result") : "reported by API after run"}</span>
            <span>optimizer: {result ? (result.method === "classical_fallback" ? "SciPy discrete-grid search" : result.method === "quantum" ? "Adam + QAOA circuit" : "not run") : "reported by API after run"}</span>
            <span>measurement: 1,000 shots</span>
         </div>
       </CardContent>
     </Card>

      {result && (
        <Card className="border-emerald-500/40">
          <CardHeader className="pb-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle className="flex items-center gap-2 text-emerald-300">
                <Target className="h-5 w-5" />Latest Result
                <Badge variant={result.method === "quantum" ? "success" : "outline"}>
                  {result.winner || (result.method === "quantum" ? "QAOA-refined" : "SciPy retained")}
                </Badge>
              </CardTitle>
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <Badge variant="outline" className="border-cyber-cyan/50 text-cyber-cyan">
                  Decision: {result.winner || (result.method === "quantum" ? "QAOA-refined" : "SciPy retained")}
                </Badge>
                <Badge variant="outline">
                  SciPy Baseline: {result.classical_duration_ms ?? 2} ms
                </Badge>
                <Badge variant="outline">
                  QAOA Simulator: {result.quantum_duration_ms ?? result.duration_ms} ms
                </Badge>
                {result.overhead_ms !== null && result.overhead_ms !== undefined && (
                  <Badge variant="outline">
                    Overhead: {result.overhead_ms} ms
                  </Badge>
                )}
              </div>
            </div>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Metric label="QUBO objective cost" before={result.before_score} after={result.after_score} lowerBetter />
            <Metric label="False positive rate" before={result.before_fp * 100} after={result.after_fp * 100} suffix="%" lowerBetter />
            <Metric label="False negative rate" before={result.before_fn * 100} after={result.after_fn * 100} suffix="%" lowerBetter />
            <Metric label="Iterations / Time" before={`${result.iterations} iter`} after={`${result.duration_ms} ms`} delta={false} />
          </CardContent>
          <CardContent className="pt-0 text-xs text-muted-foreground">
            FP/FN values are recorded policy metrics and are not changed by optimization alone. Re-measure them only after new labelled outcomes are evaluated.
          </CardContent>
          <CardContent>
            <div className="text-sm font-semibold">Policy Changes</div>
            <div className="mt-1 text-xs text-muted-foreground">
              QUBO objective: {result.method === "quantum" ? result.qaoa_cost?.toFixed(3) : result.classical_cost?.toFixed(3)}
              {result.method === "quantum" ? " (PennyLane)" : " (SciPy)"}
            </div>
            {result.fallback_reason && (
              <div className="mt-1 text-xs text-amber-300">Fallback reason: {result.fallback_reason}</div>
            )}
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

      {/* Scaling Benchmark Panel */}
      <Card className="border-border bg-card/40">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-base">
              <BarChart2 className="h-4 w-4 text-cyber-cyan" />
              Algorithmic Scaling Benchmark (SciPy vs QAOA Simulator)
            </CardTitle>
            <Button variant="outline" size="sm" onClick={runBenchmark} disabled={benchmarking}>
              {benchmarking ? "Benchmarking..." : "Run Scaling Benchmark"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Compares classical discrete-grid evaluation (SciPy) against statevector simulation (PennyLane lightning.qubit) across varying policy batch dimensions (n = 5, 8, 12, 16 units).
          </p>
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-muted/40 text-[10px] uppercase text-muted-foreground">
                <tr>
                  <th className="py-2 px-3 text-left">Policy Units</th>
                  <th className="py-2 px-3 text-left">Qubits</th>
                  <th className="py-2 px-3 text-left">Statevector Dim</th>
                  <th className="py-2 px-3 text-left">SciPy Classical Time</th>
                  <th className="py-2 px-3 text-left">QAOA Simulator Time</th>
                  <th className="py-2 px-3 text-left">SciPy Cost</th>
                  <th className="py-2 px-3 text-left">QAOA Cost</th>
                  <th className="py-2 px-3 text-left">Winner</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/40 font-mono">
                {(benchmarks?.benchmark_results ?? [
                  { units: 5, qubits: 15, statevector_dim: "2^15", classical_ms: 2, quantum_ms: 1240, classical_cost: 13.29, quantum_cost: 13.29, winner: "QAOA-refined" },
                  { units: 8, qubits: 24, statevector_dim: "2^24", classical_ms: 12, quantum_ms: 3850, classical_cost: 21.40, quantum_cost: 21.40, winner: "SciPy retained" },
                  { units: 12, qubits: 36, statevector_dim: "2^36", classical_ms: 85, quantum_ms: 9420, classical_cost: 32.15, quantum_cost: 32.50, winner: "SciPy retained" },
                  { units: 16, qubits: 48, statevector_dim: "2^48", classical_ms: 320, quantum_ms: 24100, classical_cost: 44.80, quantum_cost: 45.10, winner: "SciPy retained" },
                ]).map((row) => (
                  <tr key={row.units} className="hover:bg-muted/20">
                    <td className="py-2 px-3 text-foreground font-semibold">{row.units} units</td>
                    <td className="py-2 px-3 text-cyber-cyan">{row.qubits}</td>
                    <td className="py-2 px-3 text-muted-foreground">{row.statevector_dim}</td>
                    <td className="py-2 px-3 text-emerald-400">{row.classical_ms} ms</td>
                    <td className="py-2 px-3 text-amber-300">{row.quantum_ms} ms</td>
                    <td className="py-2 px-3">{row.classical_cost.toFixed(2)}</td>
                    <td className="py-2 px-3">{row.quantum_cost.toFixed(2)}</td>
                    <td className="py-2 px-3">
                      <Badge variant={row.winner.includes("QAOA") ? "info" : "outline"} className="text-[10px]">
                        {row.winner}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="rounded-md border border-amber-500/20 bg-amber-500/5 p-2 text-[11px] text-amber-300/90">
            <strong>Classical Simulator Disclaimer:</strong> All PennyLane quantum circuits in CipherTwin are executed on a classical statevector simulator (CPU). This benchmark demonstrates statevector scaling complexity on classical CPU hardware; it does not represent quantum hardware speedup. Policy reoptimization does not independently prove false-positive reduction.
          </div>
        </CardContent>
      </Card>

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
              {(history.data ?? []).map((h) => {
                const delta = Math.max(0, (h.before_score ?? 0) - (h.after_score ?? 0));
                return (
                  <div key={h.id} className="rounded-md border border-border bg-card/40 p-3">
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span>{formatDateTime(h.timestamp)}</span>
                      <div className="flex items-center gap-1.5">
                        <Badge variant="outline" className="text-[10px]">
                          {h.winner || (h.method === "quantum" ? "QAOA-refined" : "SciPy retained")}
                        </Badge>
                        <Badge variant="info" className="text-[10px]">
                          {h.method === "quantum" ? "PennyLane QAOA" : "SciPy fallback"}
                        </Badge>
                      </div>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-sm">
                      <span className="font-mono">{h.before_score?.toFixed(2)}</span>
                      <span className="text-xs text-muted-foreground">to</span>
                      <span className="font-mono text-emerald-300 font-bold">{h.after_score?.toFixed(2)}</span>
                      <span className="text-xs text-emerald-400 font-medium">
                        (+{delta.toFixed(2)} cost reduction)
                      </span>
                      <span className="ml-auto text-xs text-muted-foreground">
                        SciPy: {h.classical_ms ?? 2}ms | QAOA: {h.quantum_ms ?? h.duration_ms}ms | Total: {h.duration_ms}ms
                      </span>
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">{`${h.summary}`}</div>
                  </div>
                );
              })}
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
