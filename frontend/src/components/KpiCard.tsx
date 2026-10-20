import type { ReactNode } from "react";
import { TrendingDown, TrendingUp } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn, formatNumber } from "@/lib/utils";

interface KpiCardProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  accent?: "blue" | "cyan" | "green" | "red" | "amber" | "violet";
  trend?: { direction: "up" | "down"; value: string };
}

const accentMap = {
  blue: "from-cyber-blue/20 to-cyber-blue/5 text-cyber-blue",
  cyan: "from-cyber-cyan/20 to-cyber-cyan/5 text-cyber-cyan",
  green: "from-emerald-500/20 to-emerald-500/5 text-emerald-300",
  red: "from-red-500/20 to-red-500/5 text-red-300",
  amber: "from-amber-500/20 to-amber-500/5 text-amber-300",
  violet: "from-violet-500/20 to-violet-500/5 text-violet-300",
};

export function KpiCard({ label, value, hint, icon, accent = "cyan", trend }: KpiCardProps) {
  return (
    <Card className="overflow-hidden relative">
      <div
        className={cn(
          "absolute inset-x-0 top-0 h-1 bg-gradient-to-r",
          accentMap[accent].split(" ").slice(0, 2).join(" "),
        )}
      />
      <CardContent className="p-5">
        <div className="flex items-center justify-between">
          <div className="text-xs uppercase tracking-wider text-muted-foreground">{`${label}`}</div>
          {icon && (
            <div className={cn("rounded-md p-1.5 bg-gradient-to-br", accentMap[accent])}>
              {icon}
          </div>
          )}
      </div>
        <div className="mt-2 text-2xl font-bold tracking-tight">
          {typeof value === "number" ? formatNumber(value) : value}
      </div>
        <div className="mt-1 flex items-center justify-between text-xs text-muted-foreground">
          <div>{`${hint as any}`}</div>
          {trend && (
            <div
              className={cn(
                "rounded-md px-1.5 py-0.5 text-[10px] font-medium inline-flex items-center gap-1",
                trend.direction === "up"
                  ? "bg-emerald-500/15 text-emerald-300"
                  : "bg-red-500/15 text-red-300",
              )}
            >
              {trend.direction === "up" ? (
                <TrendingUp className="h-2.5 w-2.5" />
              ) : (
                <TrendingDown className="h-2.5 w-2.5" />
              )}{" "}
              {trend.value}
            </div>
          )}
      </div>
    </CardContent>
  </Card>
  );
}
