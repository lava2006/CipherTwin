import { useEffect, useState } from "react";
import { Bell, Menu, Search, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";
import type { PipelineStatus } from "@/lib/types";

interface TopbarProps {
  onMenuClick: () => void;
}

export function Topbar({ onMenuClick }: TopbarProps) {
  const [status, setStatus] = useState<PipelineStatus | null>(null);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let active = true;
    async function tick() {
      try {
        const res = await api.get<PipelineStatus>("/analytics/pipeline-status");
        if (active) setStatus(res.data);
      } catch {
        /* ignore */
      }
    }
    tick();
    const id = setInterval(tick, 4000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  const totalProcessed = status?.events_processed ?? 0;
  const totalDecisions = status?.decisions_made ?? 0;
  const totalDecoys = status?.decoys_activated ?? 0;

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
          Zero Trust • Active
       </Badge>
     </div>

      <div className="ml-4 hidden flex-1 max-w-md md:block">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search assets, telemetry, threats…"
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
