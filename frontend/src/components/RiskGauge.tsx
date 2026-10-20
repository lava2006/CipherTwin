import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { riskColor, riskLabel } from "@/lib/utils";

interface RiskGaugeProps {
  score: number;
  title?: string;
  subtitle?: string;
}

export function RiskGauge({ score, title = "Overall Risk Score", subtitle }: RiskGaugeProps) {
  const safe = Math.max(0, Math.min(100, score));
  const color = riskColor(safe);
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle>{`${title}`}</CardTitle>
        {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
    </CardHeader>
      <CardContent>
        <div className="flex items-end gap-3">
          <div
            className="text-4xl font-bold"
            style={{ color }}
          >
            {safe.toFixed(0)}
        </div>
          <div className="pb-1 text-sm font-medium" style={{ color }}>
            {riskLabel(safe)}
        </div>
      </div>
        <Progress
          value={safe}
          className="mt-3"
          indicatorClassName=""
        />
        <div className="mt-2 flex justify-between text-[10px] uppercase tracking-wider text-muted-foreground">
          <span>Low</span>
          <span>Elevated</span>
          <span>High</span>
          <span>Critical</span>
      </div>
    </CardContent>
  </Card>
  );
}
