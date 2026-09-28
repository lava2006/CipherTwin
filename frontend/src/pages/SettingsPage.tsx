import { useEffect, useState } from "react";
import { Cog, KeyRound, Moon, Sliders, UserCog } from "lucide-react";
import { SectionHeader } from "@/components/SectionHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/components/Toaster";
import { useAuth } from "@/contexts/AuthContext";

export default function SettingsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [simulation, setSimulation] = useState(true);
  const [intervalSec, setIntervalSec] = useState(2.5);
  const [threshold, setThreshold] = useState(60);

  useEffect(() => {
    const stored = localStorage.getItem("ct_theme");
    if (stored === "light") {
      setTheme("light");
      document.documentElement.classList.remove("dark");
    }
  }, []);

  function toggleTheme(t: boolean) {
    setTheme(t ? "dark" : "light");
    document.documentElement.classList.toggle("dark", t);
    localStorage.setItem("ct_theme", t ? "dark" : "light");
  }

  function save() {
    toast({ title: "Settings saved", description: "Changes are persisted in this browser.", variant: "success" });
  }

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Console Settings"
        description="Personalize your CipherTwin SOC environment."
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><UserCog className="h-4 w-4 text-cyber-cyan" />Profile</CardTitle>
        </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Label>Full name</Label>
              <Input value={user?.full_name ?? ""} readOnly />
          </div>
            <div>
              <Label>Email</Label>
              <Input value={user?.email ?? ""} readOnly />
          </div>
            <div>
              <Label>Role</Label>
              <Input value={user?.role ?? ""} readOnly />
          </div>
            <Button variant="cyber" size="sm"><KeyRound className="mr-1 h-3.5 w-3.5" />Rotate JWT secret</Button>
        </CardContent>
      </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Cog className="h-4 w-4 text-cyber-cyan" />Appearance</CardTitle>
        </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Moon className="h-4 w-4" />
                <div>
                  <div className="text-sm font-medium">Dark theme</div>
                  <div className="text-xs text-muted-foreground">Microsoft Defender-style dark mode</div>
              </div>
            </div>
              <Switch checked={theme === "dark"} onCheckedChange={toggleTheme} />
          </div>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-medium">Telemetry simulation</div>
                <div className="text-xs text-muted-foreground">Run the background worker that emits EDR-like events</div>
            </div>
              <Switch checked={simulation} onCheckedChange={setSimulation} />
          </div>
        </CardContent>
      </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><Sliders className="h-4 w-4 text-cyber-cyan" />Risk Engine Tuning</CardTitle>
        </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Label>Telemetry interval seconds</Label>
              <Input type="number" step="0.5" value={intervalSec} onChange={(e) => setIntervalSec(Number(e.target.value))} />
          </div>
            <div>
              <Label>Deception trigger risk score</Label>
              <Input type="number" min={0} max={100} value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} />
          </div>
            <Button onClick={save} variant="cyber">Save settings</Button>
            <p className="text-xs text-muted-foreground">These are stored locally for the demo. A production deployment would sync them via the API</p>
        </CardContent>
      </Card>
    </div>
  </div>
  );
}
