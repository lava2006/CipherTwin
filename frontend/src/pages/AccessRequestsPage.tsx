import { useState } from "react";
import { Download, Eye, Filter } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { RiskDecision } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { RiskBadge } from "@/components/RiskBadge";
import { Progress } from "@/components/ui/progress";
import { exportCsv, formatDateTime, riskColor } from "@/lib/utils";

const DECISIONS = ["all", "allow", "restricted", "deceive", "deny"];

export default function AccessRequestsPage() {
  const [decision, setDecision] = useState("all");
  const [page, setPage] = useState(1);
  const pageSize = 40;
  const params = new URLSearchParams();
  params.set("page", String(page));
  params.set("page_size", String(pageSize));
  if (decision !== "all") params.set("decision", decision);
  const { data, loading } = usePolling<{
    total: number;
    items: RiskDecision[];
  }>(`/risk/decisions?${params.toString()}`, 4000);

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  function handleExport() {
    exportCsv(
      "ciphertwin-decisions.csv",
      items.map((d) => ({
        id: d.id,
        timestamp: d.timestamp,
        user_id: d.user_id,
        device_id: d.device_id,
        resource_id: d.resource_id,
        risk_score: d.risk_score,
        decision: d.decision,
        confidence: d.confidence,
        summary: d.summary,
      })),
    );
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Access Requests â€“ Zero Trust Decisions"
        description="Every access evaluated by the explainable risk engine, with full factor breakdown and audit-grade metadata."
        actions={
          <Button variant="cyber" size="sm" onClick={handleExport}>
            <Download className="mr-1 h-3.5 w-3.5" /> Export CSV
      </Button>
        }
      />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Filter className="h-4 w-4 text-cyber-cyan" />
            Decision Filter
        </CardTitle>
       </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {DECISIONS.map((d) => (
            <Button
              key={d}
              size="sm"
              variant={decision === d ? "cyber" : "outline"}
              onClick={() => {
                setDecision(d);
                setPage(1);
              }}
            >
              {d}
        </Button>
          ))}
    </CardContent>
  </Card>

      <Card>
        <CardContent className="p-0">
          {loading && items.length === 0 ? (
            <div className="space-y-2 p-6">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
        </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Decision</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Summary</TableHead>
                  <TableHead>Details</TableHead>
          </TableRow>
        </TableHeader>
              <TableBody>
                {items.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="font-mono text-xs">{formatDateTime(d.timestamp)}</TableCell>
                    <TableCell className="font-mono text-xs">{`${d.user_id}`}</TableCell>
                    <TableCell className="font-mono text-xs">{`${d.resource_id}`}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span style={{ color: riskColor(d.risk_score) }} className="font-bold">
                          {d.risk_score.toFixed(0)}
                  </span>
                        <Progress value={d.risk_score} className="w-20" />
              </div>
             </TableCell>
                    <TableCell>
                      <RiskBadge decision={d.decision} />
             </TableCell>
                    <TableCell className="font-mono text-xs">{d.confidence.toFixed(0)}%</TableCell>
                    <TableCell className="max-w-[300px] truncate text-xs text-muted-foreground">
                      {d.summary}
             </TableCell>
                    <TableCell>
                      <DecisionDialog decision={d} />
             </TableCell>
           </TableRow>
                ))}
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={8} className="py-10 text-center text-sm text-muted-foreground">
                      No decisions recorded yet.
             </TableCell>
           </TableRow>
                )}
        </TableBody>
        </Table>
          )}
    </CardContent>
  </Card>

      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <div>
          Page {page} of {totalPages} â€¢ {total.toLocaleString()} decisions
    </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
            Prev
      </Button>
          <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>
            Next
      </Button>
    </div>
  </div>
</div>
  );
}

function DecisionDialog({ decision }: { decision: RiskDecision }) {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          <Eye className="h-3.5 w-3.5" />
      </Button>
    </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Decision #{decision.id} â€“ Explainability</DialogTitle>
          <DialogDescription>{formatDateTime(decision.timestamp)}</DialogDescription>
       </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <Info label="User" value={decision.user_id ?? "â€”"} />
            <Info label="Device" value={decision.device_id ?? "â€”"} />
            <Info label="Resource" value={decision.resource_id ?? "â€”"} />
            <Info label="Confidence" value={`${decision.confidence.toFixed(1)}%`} />
         </div>
          <div className="rounded-lg border border-border bg-card/40 p-4">
            <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">Risk Score</div>
            <div className="flex items-center gap-3">
              <div className="text-3xl font-bold" style={{ color: riskColor(decision.risk_score) }}>
                {decision.risk_score.toFixed(0)}
          </div>
              <RiskBadge decision={decision.decision} />
        </div>
            <Progress value={decision.risk_score} className="mt-2" />
      </div>
          <div className="rounded-lg border border-border bg-card/40 p-4">
            <div className="mb-2 text-xs uppercase tracking-wider text-muted-foreground">Contributing Factors</div>
            <div className="space-y-3">
              {decision.factors.map((f, i) => (
                <div key={i}>
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium">{`${f.name}`}</span>
                    <span className="font-mono text-xs text-muted-foreground">
                      weight {(f.weight * 100).toFixed(0)}% â€¢ score {f.score.toFixed(0)} â€¢ +{f.contribution.toFixed(1)}
             </span>
           </div>
                  <Progress value={f.score} className="mt-1" />
                  <div className="mt-1 text-xs text-muted-foreground">{`${f.description}`}</div>
         </div>
              ))}
        </div>
      </div>
          <div className="rounded-lg border border-cyber-cyan/30 bg-cyber-cyan/5 p-4 text-sm">
            <div className="mb-1 text-xs font-semibold uppercase tracking-wider text-cyber-cyan">
              Summary
        </div>
            {decision.summary}
      </div>
    </div>
  </DialogContent>
</Dialog>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{`${label}`}</div>
      <div className="font-mono text-xs">{`${value}`}</div>
  </div>
  );
}
