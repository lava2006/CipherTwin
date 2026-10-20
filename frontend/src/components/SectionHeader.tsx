import type { ReactNode } from "react";

interface SectionHeaderProps {
  title: string;
  description?: string;
  actions?: ReactNode;
}

export function SectionHeader({ title, description, actions }: SectionHeaderProps) {
  return (
    <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h2 className="text-xl font-bold tracking-tight gradient-text">{`${title}`}</h2>
        {description && (
          <p className="mt-1 text-sm text-muted-foreground">{`${description ?? ""}`}</p>
        )}
    </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
  </div>
  );
}
