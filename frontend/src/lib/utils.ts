import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(value: number | undefined | null): string {
  if (value === undefined || value === null || Number.isNaN(value)) return "—";
  if (Math.abs(value) >= 1_000_000) return (value / 1_000_000).toFixed(1) + "M";
  if (Math.abs(value) >= 1_000) return (value / 1_000).toFixed(1) + "k";
  return value.toLocaleString();
}

export function formatDateTime(input: string | null | undefined): string {
  if (!input) return "—";
  const d = new Date(input);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function timeAgo(input: string | null | undefined): string {
  if (!input) return "—";
  const d = new Date(input).getTime();
  if (Number.isNaN(d)) return "—";
  const diff = (Date.now() - d) / 1000;
  if (diff < 60) return `${Math.max(1, Math.floor(diff))}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function riskColor(score: number): string {
  if (score >= 80) return "#ef4444";
  if (score >= 60) return "#f59e0b";
  if (score >= 30) return "#22d3ee";
  return "#22c55e";
}

export function riskLabel(score: number): string {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 30) return "Elevated";
  return "Low";
}

export function decisionBadge(decision: string): { label: string; tone: string } {
  switch (decision) {
    case "allow":
      return { label: "Allowed", tone: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" };
    case "restricted":
      return { label: "Restricted", tone: "bg-amber-500/15 text-amber-300 border-amber-500/30" };
    case "deceive":
      return { label: "Deceived", tone: "bg-violet-500/15 text-violet-300 border-violet-500/30" };
    case "deny":
      return { label: "Denied", tone: "bg-red-500/15 text-red-300 border-red-500/30" };
    default:
      return { label: decision, tone: "bg-slate-500/15 text-slate-300 border-slate-500/30" };
  }
}

export function severityTone(severity: string): string {
  switch (severity) {
    case "critical":
      return "bg-red-500/15 text-red-300 border-red-500/40";
    case "high":
      return "bg-orange-500/15 text-orange-300 border-orange-500/40";
    case "medium":
      return "bg-amber-500/15 text-amber-300 border-amber-500/40";
    case "low":
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/40";
    case "warning":
      return "bg-amber-500/15 text-amber-300 border-amber-500/40";
    case "info":
      return "bg-cyan-500/15 text-cyan-300 border-cyan-500/40";
    default:
      return "bg-slate-500/15 text-slate-300 border-slate-500/40";
  }
}

export function exportCsv(filename: string, rows: Record<string, unknown>[]) {
  if (!rows.length) return;
  const headers = Object.keys(rows[0]);
  const csv = [
    headers.join(","),
    ...rows.map((r) =>
      headers
        .map((h) => {
          const v = r[h];
          if (v === null || v === undefined) return "";
          const s = String(v).replace(/"/g, '""');
          return /[",\n]/.test(s) ? `"${s}"` : s;
        })
        .join(","),
    ),
  ].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
