import { useMemo } from "react";
import {
  Activity,
  AlertOctagon,
  Eye,
  Network,
  Radar,
  Server,
  ShieldCheck,
  Sparkles,
  Users,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as ReTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { usePolling } from "@/hooks/usePolling";
import type { OverviewStats, PipelineStatus } from "@/lib/types";
import { KpiCard } from "@/components/KpiCard";
import { RiskGauge } from "@/components/RiskGauge";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { riskColor, severityTone, timeAgo } from "@/lib/utils";

const PIE_COLORS = ["#22d3ee", "#1f8ef1", "#8b5cf6", "#22c55e", "#f59e0b", "#ef4444", "#0ea5e9", "#a855f7"];

export default function OverviewPage() {
  const overview = usePolling<OverviewStats>("/analytics/overview", 6000);
  const pipeline = usePolling<PipelineStatus>("/analytics/pipeline-status", 5000);

  const stats = overview.data;
  const telemetryChartData = useMemo(() => {
    return (stats?.telemetry_by_type ?? []).map((d) => ({ name: d.event_type, count: d.count }));
  }, [stats]);

  const topAttacked = stats?.top_attacked ?? [];
  const topRisky = stats?.top_risky_users ?? [];

  const lastRisk = stats?.risk_trend.slice(-1)?.[0]?.score ?? 0;
  const riskLevel = stats?.risk_level ?? "low";
  const riskTone = severityTone(riskLevel);

  return (
    <div className="space-y-6">
      <SectionHeader
        title="SOC Command Center"
        description="Real-time Zero Trust posture, digital twin pulse, and deception coverage."
      />

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-6">
        {overview.loading && !stats ? (
          Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-28" />)
        ) : (
          <>
            <KpiCard label="Online Devices" value={`${stats?.online_devices ?? 0}`} hint={`${stats?.offline_devices ?? 0} offline`} icon={<Server className="h-4 w-4" />} accent="cyan" />
            <KpiCard label="Active Sessions" value={`${stats?.active_sessions ?? 0}`} hint="Live identities" icon={<Users className="h-4 w-4" />} accent="blue" />
            <KpiCard label="Compromised Assets" value={`${stats?.compromised_assets ?? 0}`} hint="Tracked in twin" icon={<AlertOctagon className="h-4 w-4" />} accent="red" />
            <KpiCard label="Threats Active" value={`${stats?.threats_active ?? 0}`} hint="Correlated actors" icon={<Radar className="h-4 w-4" />} accent="amber" />
            <KpiCard label="Decoys Triggered" value={`${stats?.decoy_sessions ?? 0}`} hint="Deceived attackers" icon={<Eye className="h-4 w-4" />} accent="violet" />
            <KpiCard label="Policies" value={`${stats?.policies_count ?? 0}`} hint="Zero Trust rules" icon={<ShieldCheck className="h-4 w-4" />} accent="green" />
          </>
        )}
  </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <RiskGauge score={lastRisk} subtitle={`Current posture: ${riskLevel.toUpperCase()}`} />
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Sparkles className="h-4 w-4 text-cyber-cyan" />Live Pipeline</CardTitle>
      </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <Stat label="Events processed" value={`${pipeline.data?.events_processed ?? 0}`} />
              <Stat label="Decisions emitted" value={`${pipeline.data?.decisions_made ?? 0}`} />
              <Stat label="Decoys activated" value={`${pipeline.data?.decoys_activated ?? 0}`} />
              <Stat label="Threats correlated" value={`${pipeline.data?.threats_correlated ?? 0}`} />
        </div>
            <div className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
              <span className={`inline-flex h-2 w-2 rounded-full ${pipeline.data?.running ? "bg-emerald-400 animate-pulse2" : "bg-slate-500"}`} />
              {`${pipeline.data?.running ? "Background worker running" : "Worker idle"}`}
              <span className="ml-auto">{`last event ${timeAgo(pipeline.data?.last_event_at)}`}</span>
        </div>
      </CardContent>
    </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Network className="h-4 w-4 text-cyber-cyan" />Trust Posture</CardTitle>
      </CardHeader>
          <CardContent>
            <div className="space-y-3 text-sm">
              <Row label="Trust relationships" value={`${stats?.trust_relationships ?? 0}`} />
              <Row label="Total users" value={`${stats?.total_users ?? 0}`} />
              <Row label="Telemetry 24h" value={`${stats?.total_telemetry_24h ?? 0}`} />
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Risk level</span>
                <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${riskTone}`}>{`${riskLevel}`}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4 text-cyber-cyan" />Risk Trend (24h</CardTitle>
      </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer>
              <AreaChart data={stats?.risk_trend ?? []}>
                <defs>
                  <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
              </linearGradient>
            </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="hour" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <ReTooltip contentStyle={{ backgroundColor: "#0b1220", border: "1px solid #1f8ef1", borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="score" stroke="#22d3ee" strokeWidth={2} fill="url(#riskFill)" />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4 text-cyber-cyan" />Telemetry Mix</CardTitle>
      </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer>
              <PieChart>
                <Pie data={telemetryChartData} dataKey="count" nameKey="name" innerRadius={50} outerRadius={90} stroke="#0b1220">
                  {telemetryChartData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
              </Pie>
                <ReTooltip contentStyle={{ backgroundColor: "#0b1220", border: "1px solid #1f8ef1", borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2"><CardTitle>Top Attacked Assets (24h)</CardTitle></CardHeader>
          <CardContent>
            <div className="h-72">
              <ResponsiveContainer>
                <BarChart data={topAttacked}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="label" hide />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <ReTooltip contentStyle={{ backgroundColor: "#0b1220", border: "1px solid #1f8ef1", borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                    {topAttacked.map((entry, i) => (
                      <Cell key={i} fill={riskColor(Math.min(100, entry.count * 12))} />
                    ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle>Riskiest Users (24h)</CardTitle></CardHeader>
          <CardContent>
            <div className="space-y-3">
              {topRisky.length === 0 && (
                <p className="text-sm text-muted-foreground">No risky users detected in window</p>
              )}
              {topRisky.map((u) => (
                <div key={u.user_id} className="flex items-center gap-3 rounded-md border border-border bg-card/40 p-3">
                  <div className="h-10 w-1.5 rounded-full" style={{ backgroundColor: riskColor(u.avg_risk) }} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{`${u.label}`}</div>
                    <div className="text-xs text-muted-foreground">{`${u.department} â€¢ ${u.events} decisions`}</div>
                </div>
                  <div className="text-sm font-bold" style={{ color: riskColor(u.avg_risk) }}>
                    {`${u.avg_risk.toFixed(0)}`}
                </div>
              </div>
              ))}
          </div>
        </CardContent>
      </Card>
    </div>
  </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-muted/20 p-3">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{`${label}`}</div>
      <div className="mt-1 text-lg font-semibold">{`${value}`}</div>
  </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{`${label}`}</span>
      <span className="font-semibold">{`${value}`}</span>
  </div>
  );
}
