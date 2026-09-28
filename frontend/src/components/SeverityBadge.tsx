import { Badge } from "@/components/ui/badge";
import { severityTone } from "@/lib/utils";

export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge className={severityTone(severity)}>{`${severity}`}</Badge>;
}
