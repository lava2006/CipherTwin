import { useMemo, useState } from "react";
import { Boxes, Database, Filter, RefreshCw, Server as ServerIcon, User as UserIcon, Cpu, ShieldAlert, Activity } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { TwinGraph, TwinNode } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { NetworkGraph } from "@/components/NetworkGraph";
import { riskColor, severityTone, timeAgo } from "@/lib/utils";
import { useToast } from "@/components/Toaster";
import { api } from "@/lib/api";

const TYPES: { id: TwinNode["type"]; label: string; icon: typeof Boxes }[] = [
  { id: "user", label: "Users", icon: UserIcon },
  { id: "device", label: "Devices", icon: Cpu },
  { id: "server", label: "Servers", icon: ServerIcon },
  { id: "database", label: "Databases", icon: Database },
  { id: "application", label: "Applications", icon: Boxes },
  { id: "iot", label: "IoT", icon: Activity },
  { id: "honeypot", label: "Honeypots", icon: ShieldAlert },
];

export default function NetworkTwinPage() {
  const graph = usePolling<TwinGraph>("/twin/graph", 8000);
  const [filter, setFilter] = useState<TwinNode["type"] | "all">("all");
  const [selected, setSelected] = useState<TwinNode | null>(null);
  const { toast } = useToast();

  const filtered = useMemo(() => {
    if (!graph.data) return null;
    if (filter === "all") return graph.data;
    return {
      nodes: graph.data.nodes.filter((n) => n.type === filter),
      edges: graph.data.edges,
    };
  }, [graph.data, filter]);

  async function refreshNode(id: string) {
    try {
      await api.post(`/twin/heartbeat?node_id=${encodeURIComponent(id)}`);
      toast({ title: "Node heartbeat sent", variant: "success" });
    } catch {
      toast({ title: "Heartbeat failed", variant: "error" });
    }
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Digital Twin - Enterprise Graph"
        description="Live representation of every asset, identity, and trust relationship. Backed by a Neo4j-compatible abstraction."
        actions={
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <Button
              size="sm"
              variant={filter === "all" ? "cyber" : "outline"}
              onClick={() => setFilter("all")}
            >
              All
        </Button>
            {TYPES.map((t) => (
              <Button
                key={t.id}
                size="sm"
                variant={filter === t.id ? "cyber" : "outline"}
                onClick={() => setFilter(t.id)}
              >
                {t.label}
          </Button>
            ))}
      </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        {TYPES.map((t) => {
          const count = graph.data?.nodes.filter((n) => n.type === t.id).length ?? 0;
          return (
            <Card key={t.id}>
              <CardContent className="flex items-center gap-3 p-4">
                <div className={`rounded-md p-2 ${t.id === "honeypot" ? "bg-rose-500/10 text-rose-400" : "bg-cyber-cyan/10 text-cyber-cyan"}`}>
                  <t.icon className="h-4 w-4" />
            </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{`${t.label}`}</div>
                  <div className="text-xl font-bold">{`${count}`}</div>
          </div>
        </CardContent>
      </Card>
          );
        })}
  </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle>Graph Visualization</CardTitle>
            <Badge variant="info" className="font-mono">
              {filtered?.nodes.length ?? 0} nodes / {filtered?.edges.length ?? 0} edges
        </Badge>
      </CardHeader>
          <CardContent>
            {graph.loading && !filtered ? (
              <Skeleton className="h-[520px] w-full" />
            ) : filtered ? (
              <NetworkGraph
                graph={filtered}
                highlightNodeId={selected?.id}
                onSelect={setSelected}
                height={520}
              />
            ) : (
              <p className="text-sm text-muted-foreground">No data</p>
            )}
      </CardContent>
    </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Selected Asset</CardTitle>
         </CardHeader>
          <CardContent>
            {selected ? (
              <div className="space-y-3 text-sm">
                <div className="flex items-center gap-3">
                  <div
                    className="h-12 w-12 rounded-lg flex items-center justify-center font-bold"
                    style={{ backgroundColor: selected.type === "honeypot" ? "#f43f5e" : riskColor(selected.risk_score), color: "#fff" }}
                  >
                    {selected.type === "honeypot" ? "🪤" : <ShieldAlert className="h-5 w-5" />}
            </div>
                  <div>
                    <div className="font-semibold">{`${selected.label}`}</div>
                    <div className="text-xs text-muted-foreground">{`${selected.id}`}</div>
            </div>
          </div>
                {selected.type === "honeypot" && (
                  <div className="rounded-md border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-200">
                    <span className="font-semibold text-rose-300">Cowrie SSH Decoy Trap:</span> Deployed in DMZ to intercept attacker reconnaissance and lateral movement.
                  </div>
                )}
                <Row label="Type" value={selected.type} />
                <Row label="IP" value={selected.ip_address ?? "N/A"} />
                <Row label="Location" value={selected.location ?? "N/A"} />
                <Row label="Department" value={selected.department ?? "N/A"} />
                <Row label="OS" value={selected.os ?? "N/A"} />
                {selected.type === "honeypot" && (
                  <>
                    <Row label="Decoy Software" value="Cowrie 2.5 (SSH/Telnet)" />
                    <Row label="Interaction Level" value="Medium-Interaction" />
                    <Row label="Trap Link" value="FS-01 File Server (traps)" />
                  </>
                )}
                <Row label="Sensitivity" value={selected.sensitivity} />
                <Row label="Trust" value={`${selected.trust_score.toFixed(0)}%`} />
                <Row label="Risk" value={`${selected.risk_score.toFixed(0)}`} />
                <Row label="Last seen" value={timeAgo(selected.last_seen)} />
                <div className="flex items-center gap-2 pt-2">
                  <Badge className={selected.type === "honeypot" ? "bg-rose-500/20 text-rose-400 border-rose-500/40" : severityTone(selected.status)}>
                    {selected.type === "honeypot" ? "🪤 HONEYPOT DECOY" : `${selected.status}`}
                  </Badge>
                  <Button size="sm" variant="cyber" onClick={() => refreshNode(selected.id)}>
                    <RefreshCw className="mr-1 h-3.5 w-3.5" /> Heartbeat
              </Button>
        </div>
      </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                Click a node in the graph to inspect its posture.
            </p>
            )}
      </CardContent>
    </Card>
  </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle>Asset Inventory</CardTitle>
       </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                <tr className="border-b border-border">
                  <th className="px-3 py-2">Asset</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">IP</th>
                  <th className="px-3 py-2">Location</th>
                  <th className="px-3 py-2">Sensitivity</th>
                  <th className="px-3 py-2">Trust</th>
                  <th className="px-3 py-2">Status</th>
          </tr>
        </thead>
              <tbody>
                {(filtered?.nodes ?? []).map((n) => (
                  <tr
                    key={n.id}
                    onClick={() => setSelected(n)}
                    className="cursor-pointer border-b border-border/50 hover:bg-muted/20"
                  >
                    <td className="px-3 py-2">
                      <div className="font-medium">{`${n.label}`}</div>
                      <div className="text-xs text-muted-foreground">{`${n.id}`}</div>
             </td>
                    <td className="px-3 py-2 capitalize">{`${n.type}`}</td>
                    <td className="px-3 py-2 font-mono text-xs">{n.ip_address ?? "N/A"}</td>
                    <td className="px-3 py-2">{n.location ?? "N/A"}</td>
                    <td className="px-3 py-2 capitalize">{`${n.sensitivity}`}</td>
                    <td className="px-3 py-2">
                      <span style={{ color: riskColor(100 - n.trust_score) }}>{n.trust_score.toFixed(0)}%</span>
             </td>
                    <td className="px-3 py-2">
                      <Badge className={severityTone(n.status)}>{`${n.status}`}</Badge>
             </td>
           </tr>
                ))}
             </tbody>
         </table>
      </div>
    </CardContent>
  </Card>
</div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-muted-foreground">{`${label}`}</span>
      <span className="font-medium">{`${value as any}`}</span>
  </div>
  );
}
