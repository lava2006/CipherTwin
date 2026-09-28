import { useState } from "react";
import { Eye, Fingerprint, Plus, Terminal, Webhook } from "lucide-react";
import { usePolling } from "@/hooks/usePolling";
import type { DecoySession, Honeytoken } from "@/lib/types";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/Toaster";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/utils";

const ICONS: Record<string, JSX.Element> = {
  ssh: <Terminal className="h-4 w-4" />,
  database: <Fingerprint className="h-4 w-4" />,
  web: <Webhook className="h-4 w-4" />,
  admin_panel: <Eye className="h-4 w-4" />,
};

export default function DeceptionPage() {
  const sessions = usePolling<DecoySession[]>("/deception/sessions", 6000);
  const tokens = usePolling<Honeytoken[]>("/deception/honeytokens", 8000);
  const [active, setActive] = useState<DecoySession | null>(null);
  const { toast } = useToast();

  async function reseed() {
    try {
      await api.post("/deception/seed");
      toast({ title: "Honeytokens planted", description: "Fake credentials and decoy files distributed.", variant: "success" });
    } catch {
      toast({ title: "Seed failed", variant: "error" });
    }
  }

  async function trigger(id: number) {
    try {
      await api.post(`/deception/trigger/${id}`);
      toast({ title: "Honeytoken triggered", description: "Attacker behaviour recorded.", variant: "warning" });
    } catch {
      toast({ title: "Trigger failed", variant: "error" });
    }
  }

  const list = sessions.data ?? [];
  const tokenList = tokens.data ?? [];

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Adaptive Deception Engine"
        description="High-risk sessions are redirected into believable decoys. Honeytokens record every interaction."
        actions={
          <Button variant="cyber" size="sm" onClick={reseed}>
            <Plus className="mr-1 h-3.5 w-3.5" /> Plant Honeytokens
  </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle>Active Decoy Sessions</CardTitle>
   </CardHeader>
          <CardContent className="space-y-2">
            {sessions.loading && !list.length ? (
              Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)
            ) : (
              list.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setActive(s)}
                  className={`w-full text-left rounded-lg border p-3 transition-colors ${active?.id === s.id ? "border-cyber-violet/40 bg-violet-500/10" : "border-border bg-card/40 hover:bg-muted/30"}`}
                >
                  <div className="flex items-center gap-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-md bg-violet-500/20 text-violet-300">
                      {ICONS[s.decoy_type] ?? <Eye className="h-4 w-4" />}
          </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-semibold capitalize">{`${s.decoy_type.replace("_", " ")} Decoy`}</div>
                      <div className="truncate text-xs text-muted-foreground">{`Actor: ${s.actor ?? "â€”"} â€¢ IP ${s.source_ip ?? "â€”"}`}</div>
        </div>
                    <Badge variant="violet">{`${formatDateTime(s.timestamp)}`}</Badge>
      </div>
        </button>
              ))
            )}
            {list.length === 0 && (
              <p className="text-sm text-muted-foreground">No decoy sessions yet. Risky traffic will be redirected here automatically</p>
            )}
   </CardContent>
 </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Session Detail</CardTitle>
      </CardHeader>
          <CardContent>
            {active ? (
              <div className="space-y-4 text-sm">
                <div className="rounded-md border border-violet-500/30 bg-violet-500/5 p-3">
                  <div className="text-xs uppercase tracking-wider text-violet-300">Notes</div>
                  <div>{`${active.notes}`}</div>
        </div>
                <div>
                  <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">Credentials used</div>
                  <div className="rounded-md bg-muted/30 p-2 font-mono text-xs">{`${active.credentials_used ?? "â€”"}`}</div>
        </div>
                <div>
                  <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">Activity timeline</div>
                  <ul className="space-y-1 text-xs">
                    {(active.activity ?? []).map((a, i) => (
                      <li key={i} className="rounded bg-muted/30 px-2 py-1">{`${a}`}</li>
                    ))}
        </ul>
        </div>
                <div>
                  <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">Commands</div>
                  <ul className="space-y-1 font-mono text-xs">
                    {(active.commands ?? []).map((c, i) => (
                      <li key={i} className="rounded bg-muted/30 px-2 py-1 text-emerald-300">{`$ ${c}`}</li>
                    ))}
          </ul>
        </div>
                <div>
                  <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">Pages visited</div>
                  <ul className="space-y-1 font-mono text-xs">
                    {(active.pages ?? []).map((p, i) => (
                      <li key={i} className="rounded bg-muted/30 px-2 py-1 text-cyan-300">{`GET ${p}`}</li>
                    ))}
          </ul>
        </div>
      </div>
            ) : (
              <p className="text-sm text-muted-foreground">Select a decoy session to inspect what the attacker did</p>
            )}
  </CardContent>
</Card>
</div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle>Honeytokens</CardTitle>
   </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                <tr className="border-b border-border">
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Label</th>
                  <th className="px-3 py-2">Value</th>
                  <th className="px-3 py-2">Planted on</th>
                  <th className="px-3 py-2">Triggered</th>
                  <th className="px-3 py-2">Action</th>
      </tr>
    </thead>
              <tbody>
                {tokenList.map((t) => (
                  <tr key={t.id} className="border-b border-border/40 hover:bg-muted/20">
                    <td className="px-3 py-2 capitalize">{`${t.token_type}`}</td>
                    <td className="px-3 py-2 font-medium">{`${t.label}`}</td>
                    <td className="px-3 py-2 font-mono text-xs">{`${t.value}`}</td>
                    <td className="px-3 py-2">{`${t.planted_on ?? "â€”"}`}</td>
                    <td className="px-3 py-2">
                      <Badge variant={t.triggered ? "danger" : "outline"}>{`${t.triggered ? "Triggered" : "Armed"}`}</Badge>
         </td>
                    <td className="px-3 py-2">
                      <Button size="sm" variant="outline" onClick={() => trigger(t.id)}>
                        Simulate trigger
         </Button>
         </td>
       </tr>
                ))}
                {tokenList.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-3 py-6 text-center text-sm text-muted-foreground">
                      No honeytokens yet. Click Plant Honeytokens to distribute.
           </td>
       </tr>
                )}
    </tbody>
  </table>
</div>
</CardContent>
</Card>
</div>
  );
}
