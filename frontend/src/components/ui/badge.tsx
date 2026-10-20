import * as React from "react";
import { cn } from "@/lib/utils";

type BadgeProps = React.HTMLAttributes<HTMLDivElement> & {
  variant?: "default" | "outline" | "success" | "warning" | "danger" | "info" | "violet";
};

export function Badge({ className, variant = "default", ...props }: BadgeProps) {
  const tones: Record<string, string> = {
    default: "bg-secondary text-secondary-foreground border-border",
    outline: "bg-transparent text-foreground border-border",
    success: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
    warning: "bg-amber-500/15 text-amber-300 border-amber-500/40",
    danger: "bg-red-500/15 text-red-300 border-red-500/40",
    info: "bg-cyan-500/15 text-cyan-300 border-cyan-500/40",
    violet: "bg-violet-500/15 text-violet-300 border-violet-500/40",
  };
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors",
        tones[variant],
        className,
      )}
      {...props}
    />
  );
}
