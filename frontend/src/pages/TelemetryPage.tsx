import { useMemo, useState } from "react";
import { Download, Filter, RefreshCw, Search } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { TelemetryEvent } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { exportCsv, formatDateTime, severityTone } from "@/lib/utils";
import { EventSimulator } from "@/components/EventSimulator";

const EVENT_TYPES = [
  "all",
  "login",
  "file_access",
  "network_request",
  "failed_login",
  "privilege_escalation",
  "powershell",
  "usb_insertion",
  "abnormal_process",
  "lateral_movement",
  "data_exfiltration",
  "ssh_attempt",
  "geolocation_change",
];

export default function TelemetryPage() {
  const [eventType, setEventType] = useState("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 50;
  const params = new URLSearchParams();
  params.set("page", String(page));
  params.set("page_size", String(pageSize));
  if (eventType !== "all") params.set("event_type", eventType);
  if (search) params.set("search", search);
  const { data, loading } = usePolling<{
    total: number;
    page: number;
    page_size: number;
    items: TelemetryEvent[];
  }>(`/telemetry?${params.toString()}`, 4000);

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  function handleExport() {
    exportCsv(
      "ciphertwin-telemetry.csv",
      items.map((it) => ({
        id: it.id,
        timestamp: it.timestamp,
        user_id: it.user_id,
        device_id: it.device_id,
        target_id: it.target_id,
        event_type: it.event_type,
        location: it.location,
        ip_address: it.ip_address,
        status: it.status,
        indicators: it.risk_indicators.join("|"),
      })),
    );
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Telemetry Stream"
        description="High-fidelity simulated EDR signal: logins, file access, network, PowerShell, USB, lateral movement, and more."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                placeholder="Search user, IP, location..."
                className="h-9 w-56 pl-7"
              />
        </div>
            <Button variant="outline" size="sm" onClick={() => setPage(1)}>
              <RefreshCw className="mr-1 h-3.5 w-3.5" /> Reset
        </Button>
            <Button variant="cyber" size="sm" onClick={handleExport}>
              <Download className="mr-1 h-3.5 w-3.5" /> Export CSV
        </Button>
      </div>
        }
      />

      <EventSimulator />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Filter className="h-4 w-4 text-cyber-cyan" />
            Event Filter
        </CardTitle>
       </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {EVENT_TYPES.map((t) => (
            <Button
              key={t}
              size="sm"
              variant={eventType === t ? "cyber" : "outline"}
              onClick={() => {
                setEventType(t);
                setPage(1);
              }}
            >
              {t.replace("_", " ")}
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
                  <TableHead>Event</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Location</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Indicators</TableHead>
          </TableRow>
        </TableHeader>
              <TableBody>
                {items.map((it) => (
                  <TableRow key={it.id}>
                    <TableCell className="font-mono text-xs">{formatDateTime(it.timestamp)}</TableCell>
                    <TableCell className="font-medium">{it.event_type.replace("_", " ")}</TableCell>
                    <TableCell className="font-mono text-xs">{`${it.user_id}`}</TableCell>
                    <TableCell className="font-mono text-xs">{`${it.device_id}`}</TableCell>
                    <TableCell className="font-mono text-xs">{`${it.target_id}`}</TableCell>
                    <TableCell>{it.location ?? "N/A"}</TableCell>
                    <TableCell className="font-mono text-xs">{it.ip_address ?? "N/A"}</TableCell>
                    <TableCell>
                      <Badge className={severityTone(it.status === "failure" ? "warning" : "info")}>
                        {it.status}
              </Badge>
             </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {it.risk_indicators.map((ind) => (
                          <Badge key={ind} variant="outline" className="font-mono text-[10px]">
                            {ind}
                    </Badge>
                        ))}
                </div>
             </TableCell>
           </TableRow>
                ))}
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={9} className="py-10 text-center text-sm text-muted-foreground">
                      No telemetry events match the filter yet - give the simulator a few seconds.
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
          Page {page} of {totalPages} | {total.toLocaleString()} events
    </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            Prev
      </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            Next
      </Button>
    </div>
  </div>
</div>
  );
}
