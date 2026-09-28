import { useState } from "react";
import { Download, FileText, Search } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { AuditLog } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { exportCsv, formatDateTime, severityTone } from "@/lib/utils";

const SEVERITIES = ["all", "info", "warning", "critical"];

export default function AuditPage() {
  const [severity, setSeverity] = useState("all");
  const [search, setSearch] = useState("");
  const params = new URLSearchParams();
  if (severity !== "all") params.set("severity", severity);
  if (search) params.set("action", search);
  const { data, loading } = usePolling<{ total: number; items: AuditLog[] }>(
    `/audit?${params.toString()}`,
    5000,
  );
  const items = data?.items ?? [];

  function handleExport() {
    exportCsv(
      "ciphertwin-audit.csv",
      items.map((i) => ({
        id: i.id,
        timestamp: i.timestamp,
        actor: i.actor,
        action: i.action,
        target: i.target,
        details: i.details,
        severity: i.severity,
        ip_address: i.ip_address,
      })),
    );
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Audit Logs"
        description="Every consequential action: logins, policy changes, risk decisions, decoy activations, optimization runs."
        actions={
          <Button variant="cyber" size="sm" onClick={handleExport}>
            <Download className="mr-1 h-3.5 w-3.5" /> Export CSV
     </Button>
        }
      />

      <Card>
        <CardContent className="flex flex-col gap-3 p-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search action (e.g. login, optimize)"
              className="h-9 w-72"
            />
         </div>
          <div className="flex items-center gap-2">
            {SEVERITIES.map((s) => (
              <Button
                key={s}
                size="sm"
                variant={severity === s ? "cyber" : "outline"}
                onClick={() => setSeverity(s)}
              >
                {s}
             </Button>
            ))}
         </div>
       </CardContent>
     </Card>

      <Card>
        <CardContent className="p-0">
          {loading && items.length === 0 ? (
            <div className="space-y-2 p-6">
              {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
           </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Details</TableHead>
               </TableRow>
             </TableHeader>
              <TableBody>
                {items.map((it) => (
                  <TableRow key={it.id}>
                    <TableCell className="font-mono text-xs">{formatDateTime(it.timestamp)}</TableCell>
                    <TableCell>{it.actor ?? "â€”"}</TableCell>
                    <TableCell className="font-medium">{`${it.action}`}</TableCell>
                    <TableCell className="font-mono text-xs">{it.target ?? "â€”"}</TableCell>
                    <TableCell>
                      <Badge className={severityTone(it.severity)}>{`${it.severity}`}</Badge>
                   </TableCell>
                    <TableCell className="font-mono text-xs">{it.ip_address ?? "â€”"}</TableCell>
                    <TableCell className="max-w-[360px] truncate text-xs text-muted-foreground">
                      {it.details ?? "â€”"}
                   </TableCell>
                 </TableRow>
                ))}
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="py-10 text-center text-sm text-muted-foreground">
                      <FileText className="mx-auto mb-2 h-6 w-6 text-muted-foreground" />
                      No audit entries match the filter.
                   </TableCell>
                 </TableRow>
                )}
             </TableBody>
           </Table>
          )}
       </CardContent>
     </Card>
   </div>
  );
}
