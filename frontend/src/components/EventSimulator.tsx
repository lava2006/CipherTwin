import { useState } from "react";
import { Play, Square, Activity, Radio, Cpu, Clock, CheckCircle2 } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/components/Toaster";
import { timeAgo } from "@/lib/utils";

interface EventEngineStatus {
  running: boolean;
  state: "RUNNING" | "STOPPED";
  events_generated: number;
  events_per_second: number;
  last_event_at: string | null;
  rabbitmq_connected?: boolean;
  recent_events?: Array<{
    user_id: string;
    event_type: string;
    ip_address: string;
    timestamp: string;
    is_anomaly: boolean;
  }>;
}

export function EventSimulator() {
  const { data: status, refetch } = usePolling<EventEngineStatus>("/events/status", 1000);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const isRunning = status?.running ?? false;

  async function handleStart() {
    setLoading(true);
    try {
      await api.post("/events/start");
      toast({
        title: "Event Engine Started",
        description: "Generating telemetry at strictly 1 event/sec cadence.",
        variant: "success",
      });
      if (refetch) refetch();
    } catch {
      toast({
        title: "Failed to Start Engine",
        description: "Could not start backend telemetry engine.",
        variant: "error",
      });
    } finally {
      setLoading(false);
    }
  }

  async function handleStop() {
    setLoading(true);
    try {
      await api.post("/events/stop");
      toast({
        title: "Event Engine Stopped",
        description: "Telemetry generation paused (0 event/sec).",
        variant: "default",
      });
      if (refetch) refetch();
    } catch {
      toast({
        title: "Failed to Stop Engine",
        description: "Could not stop backend telemetry engine.",
        variant: "error",
      });
    } finally {
      setLoading(false);
    }
  }

  const latestEvent = status?.recent_events && status.recent_events.length > 0
    ? status.recent_events[status.recent_events.length - 1]
    : null;

  return (
    <Card className="border-cyber-cyan/30 bg-cyber-panel/80 shadow-lg shadow-cyber-cyan/5">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div className="flex items-center gap-2">
          <Radio className={`h-5 w-5 ${isRunning ? "text-emerald-400 animate-pulse" : "text-muted-foreground"}`} />
          <div>
            <CardTitle className="text-base font-semibold">Authoritative Event Engine</CardTitle>
            <p className="text-xs text-muted-foreground">
              Controlled backend generator (Strict 1 event/sec, START/STOP state machine)
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Badge
            className={`font-mono text-xs px-2.5 py-1 flex items-center gap-1.5 ${
              isRunning
                ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                : "bg-slate-700/40 text-slate-300 border border-slate-600/40"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                isRunning ? "bg-emerald-400 animate-ping" : "bg-slate-400"
              }`}
            />
            {isRunning ? "RUNNING (1 evt/s)" : "STOPPED (0 evt/s)"}
          </Badge>

          <div className="flex items-center gap-1.5">
            <Button
              size="sm"
              variant={isRunning ? "outline" : "cyber"}
              disabled={isRunning || loading}
              onClick={handleStart}
              className="h-8 gap-1 text-xs"
            >
              <Play className="h-3.5 w-3.5 fill-current" /> START
            </Button>
            <Button
              size="sm"
              variant={isRunning ? "destructive" : "outline"}
              disabled={!isRunning || loading}
              onClick={handleStop}
              className="h-8 gap-1 text-xs"
            >
              <Square className="h-3.5 w-3.5 fill-current" /> STOP
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-lg border border-border/60 bg-muted/20 p-2.5">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Activity className="h-3.5 w-3.5 text-cyber-cyan" /> Events Generated
            </div>
            <div className="mt-1 font-mono text-xl font-bold text-foreground">
              {status?.events_generated?.toLocaleString() ?? 0}
            </div>
          </div>

          <div className="rounded-lg border border-border/60 bg-muted/20 p-2.5">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Clock className="h-3.5 w-3.5 text-cyber-cyan" /> Generation Cadence
            </div>
            <div className="mt-1 font-mono text-xl font-bold text-foreground">
              {isRunning ? "1.0 / sec" : "0.0 / sec"}
            </div>
          </div>

          <div className="rounded-lg border border-border/60 bg-muted/20 p-2.5">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Cpu className="h-3.5 w-3.5 text-cyber-cyan" /> Pipeline Queue
            </div>
            <div className="mt-1 text-xs font-semibold text-foreground">
              {status?.rabbitmq_connected ? "RabbitMQ (AMQP)" : "In-Memory Buffer"}
            </div>
          </div>

          <div className="rounded-lg border border-border/60 bg-muted/20 p-2.5">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <CheckCircle2 className="h-3.5 w-3.5 text-cyber-cyan" /> Last Event Emitted
            </div>
            <div className="mt-1 font-mono text-xs font-medium text-foreground">
              {status?.last_event_at ? timeAgo(status.last_event_at) : "None yet"}
            </div>
          </div>
        </div>

        {latestEvent && (
          <div className="flex items-center justify-between rounded-md border border-border/40 bg-muted/10 px-3 py-1.5 text-xs">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-cyber-cyan">Latest Telemetry:</span>
              <span className="font-mono text-foreground">{latestEvent.user_id}</span>
              <span className="text-muted-foreground">|</span>
              <span className="font-medium text-amber-300">{latestEvent.event_type}</span>
              <span className="text-muted-foreground">|</span>
              <span className="font-mono text-muted-foreground">{latestEvent.ip_address}</span>
            </div>
            {latestEvent.is_anomaly && (
              <Badge variant="danger" className="text-[10px] uppercase">
                Anomaly Flagged
              </Badge>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
