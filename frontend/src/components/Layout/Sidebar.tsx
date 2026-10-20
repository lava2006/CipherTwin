import { NavLink, useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  Bot,
  Boxes,
  ChevronLeft,
  CircleGauge,
  Cog,
  Eye,
  FileText,
  LayoutDashboard,
  LifeBuoy,
  LogOut,
  Network,
  Radar,
  Shield,
  Sparkles,
  Workflow,
} from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Button } from "@/components/ui/button";

const NAV_GROUPS = [
  {
    title: "SOC Operations",
    items: [
      { to: "/dashboard", label: "Overview", icon: LayoutDashboard },
      { to: "/twin", label: "Network Twin", icon: Network },
      { to: "/telemetry", label: "Telemetry", icon: Activity },
      { to: "/access-requests", label: "Access Requests", icon: Shield },
      { to: "/risk", label: "Risk Analytics", icon: CircleGauge },
    ],
  },
  {
    title: "Threat Response",
    items: [
      { to: "/threats", label: "Threat Intelligence", icon: Radar },
      { to: "/deception", label: "Deception Logs", icon: Eye },
      { to: "/optimization", label: "Quantum Optimization", icon: Sparkles },
      { to: "/policies", label: "Policy History", icon: Workflow },
    ],
  },
  {
    title: "Governance",
    items: [
      { to: "/audit", label: "Audit Logs", icon: FileText },
      { to: "/explainer", label: "Explainability", icon: Bot },
      { to: "/settings", label: "Settings", icon: Cog },
    ],
  },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <TooltipProvider delayDuration={250}>
      <aside
        className={cn(
          "relative flex h-full flex-col border-r border-border bg-cyber-panel/80 backdrop-blur-md transition-all duration-300",
          collapsed ? "w-[68px]" : "w-64",
        )}
      >
        <div className="flex h-16 items-center justify-between border-b border-border px-4">
          <div className="flex items-center gap-2 overflow-hidden">
            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-gradient-to-br from-cyber-blue to-cyber-cyan text-white shadow-lg shadow-cyan-500/30">
              <Boxes className="h-5 w-5" />
           </div>
            {!collapsed && (
              <div>
                <div className="text-sm font-bold tracking-tight gradient-text">CipherTwin</div>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Cyber Defense</div>
             </div>
            )}
         </div>
          <Button
            size="icon"
            variant="ghost"
            onClick={onToggle}
            className="h-7 w-7"
            aria-label="Toggle sidebar"
          >
            <ChevronLeft
              className={cn("h-4 w-4 transition-transform", collapsed && "rotate-180")}
            />
         </Button>
       </div>

        <nav className="flex-1 overflow-y-auto py-3">
          {NAV_GROUPS.map((group) => (
            <div key={group.title} className="px-2 pb-3">
              {!collapsed && (
                <div className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                  {group.title}
               </div>
              )}
              <div className="space-y-0.5">
                {group.items.map((item) => (
                  <Tooltip key={item.to}>
                    <TooltipTrigger asChild>
                      <NavLink
                        to={item.to}
                        className={({ isActive }) =>
                          cn(
                            "group flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                            isActive
                              ? "bg-gradient-to-r from-cyber-blue/20 to-cyber-cyan/10 text-white border border-cyber-cyan/30"
                              : "text-muted-foreground hover:bg-muted/40 hover:text-foreground",
                          )
                        }
                      >
                        <item.icon className="h-4 w-4 shrink-0" />
                        {!collapsed && <span className="truncate">{item.label}</span>}
                     </NavLink>
                   </TooltipTrigger>
                    {collapsed && (
                      <TooltipContent side="right">{`${item.label}`}</TooltipContent>
                    )}
                 </Tooltip>
                ))}
             </div>
           </div>
          ))}
       </nav>

        <div className="border-t border-border p-3">
          {!collapsed && (
            <div className="mb-3 rounded-lg glass p-3">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <LifeBuoy className="h-4 w-4 text-cyber-cyan" />
                <span>Pipeline</span>
             </div>
              <PipelinePulse />
           </div>
          )}
          <div className={cn("flex items-center gap-2", collapsed && "justify-center")}>
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-cyber-blue to-cyber-violet text-xs font-bold">
              {user?.full_name?.[0] ?? "?"}
           </div>
            {!collapsed && (
              <div className="flex-1 min-w-0">
                <div className="truncate text-sm font-medium">{`${user?.full_name ?? ""}`}</div>
                <div className="truncate text-[10px] uppercase text-muted-foreground">
                  {user?.role}
               </div>
             </div>
            )}
            {!collapsed && (
              <Button
                size="icon"
                variant="ghost"
                onClick={() => {
                  logout();
                  navigate("/login");
                }}
                aria-label="Logout"
              >
                <LogOut className="h-4 w-4" />
             </Button>
            )}
         </div>
       </div>
     </aside>
   </TooltipProvider>
  );
}

function PipelinePulse() {
  return (
    <div className="mt-2 flex items-center gap-2 text-xs">
      <span className="relative inline-flex h-2 w-2">
        <span className="absolute inset-0 animate-ping rounded-full bg-emerald-400 opacity-70" />
        <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
     </span>
      <span className="text-emerald-300">Telemetry stream active</span>
   </div>
  );
}
