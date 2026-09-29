import { useEffect, useState } from "react";
import { Activity, AlertTriangle, Bell, CheckCircle2, Menu, Search, ShieldCheck, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { api } from "@/lib/api";
import type { PipelineStatus, SystemHealth } from "@/lib/types";

interface TopbarProps {
  onMenuClick: () => void;
}

export function Topbar({ onMenuClick }: TopbarProps) {
  const [status, setStatus] = useState<PipelineStatus | null>(null);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let active = true;
    async function tick() {
      try {
        const [resPipe, resHealth] = await Promise.all([
          api.get<PipelineStatus>("/analytics/pipeline-status"),
          api.get<SystemHealth>("/system/health"),
        ]);
        if (active) {
          setStatus(resPipe.data);
          setHealth(resHealth.data);
        }
      } catch {
        /* ignore */
      }
    }
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  const totalProcessed = status?.events_processed ?? 0;
  const totalDecisions = status?.decisions_made ?? 0;
  const totalDecoys = status?.decoys_activated ?? 0;

  const healthVariant =
    health?.status === "HEALTHY" ? "success" : health?.status === "DEGRADED" ? "warning" : "danger";

  return (
    <header className="sticky top-0 z-40 flex h-16 items-center gap-3 border-b border-border bg-cyber-panel/80 px-4 backdrop-blur-md">
      <Button
        variant="ghost"
        size="icon"
        onClick={onMenuClick}
        className="lg:hidden"
        aria-label="Menu"
      >
        <Menu className="h-5 w-5" />
      </Button>

      <div className="flex items-center gap-2 text-sm">
        <ShieldCheck className="h-5 w-5 text-cyber-cyan" />
        <span className="font-semibold gradient-text">CipherTwin</span>
        <Badge variant="info" className="ml-2 hidden sm:inline-flex">
          Zero Trust | Active
        </Badge>

        <Dialog>
          <DialogTrigger asChild>
            <Button variant="ghost" size="sm" className="h-7 px-2">
              <Badge variant={healthVariant} className="cursor-pointer gap-1 text-[11px]">
                <Activity className="h-3 w-3" />
                {health?.status ? `System: ${health.status}` : "System: Checking..."}
              </Badge>
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-xl">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-cyber-cyan" />
                Subsystem Runtime Health
              </DialogTitle>
              <DialogDescription>
                Truthful, real-time status across all 8 core services (no simulated claims).
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-3 py-2">
              {health?.services ? (
                Object.entries(health.services).map(([key, svc]) => (
                  <div key={key} className="flex items-start justify-between rounded-lg border border-border bg-card/40 p-3">
                    <div>
                      <div className="flex items-center gap-2 font-semibold capitalize text-sm">
                        {key.replace("_", " ")}
                        <Badge
                          variant={
                            svc.status === "HEALTHY"
                              ? "success"
                              : svc.status === "DEGRADED"
                              ? "warning"
                              : "danger"
                          }
                          className="text-[10px]"
                        >
                          {svc.status}
                        </Badge>
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">{svc.message}</div>
                    </div>
                    {svc.status === "HEALTHY" ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-1" />
                    ) : svc.status === "DEGRADED" ? (
                      <AlertTriangle className="h-4 w-4 text-amber-400 mt-1" />
                    ) : (
                      <XCircle className="h-4 w-4 text-rose-400 mt-1" />
                    )}
                  </div>
                ))
              ) : (
                <div className="text-center text-sm text-muted-foreground">Loading subsystem health...</div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="ml-4 hidden flex-1 max-w-md md:block">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search assets, telemetry, threats..."
            className="pl-9"
          />
        </div>
      </div>

      <div className="ml-auto flex items-center gap-3">
        <div className="hidden items-center gap-4 text-xs text-muted-foreground md:flex">
          <Stat label="Events" value={totalProcessed} />
          <Stat label="Decisions" value={totalDecisions} />
          <Stat label="Decoys" value={totalDecoys} />
        </div>
        <Button size="icon" variant="ghost" aria-label="Notifications">
          <Bell className="h-5 w-5" />
        </Button>
      </div>
    </header>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col items-end">
      <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
      <span className="text-sm font-semibold text-foreground">{value.toLocaleString()}</span>
    </div>
  );
}
