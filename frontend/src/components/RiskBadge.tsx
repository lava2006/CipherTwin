import { Badge } from "@/components/ui/badge";
import { decisionBadge } from "@/lib/utils";

export function RiskBadge({ decision }: { decision: string }) {
  const meta = decisionBadge(decision);
  return <Badge className={meta.tone}>{`${meta.label}`}</Badge>;
}
