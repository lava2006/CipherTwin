import { Inbox } from "lucide-react";
import type { ReactNode } from "react";

interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}

export function EmptyState({ title, description, icon, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-card/40 p-8 text-center">
      <div className="mb-3 rounded-full bg-muted p-3 text-muted-foreground">
        {icon ?? <Inbox className="h-5 w-5" />}
    </div>
      <div className="text-sm font-semibold">{`${title}`}</div>
      {description && (
        <p className="mt-1 max-w-sm text-xs text-muted-foreground">{`${description ?? ""}`}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
  </div>
  );
}
