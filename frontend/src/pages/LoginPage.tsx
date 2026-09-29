import { useState, type FormEvent } from "react";
import { useNavigate, Navigate } from "react-router-dom";
import { Boxes, Eye, EyeOff, Loader2, ShieldCheck } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { useToast } from "@/components/Toaster";

export default function LoginPage() {
  const { user, login } = useAuth();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [showPwd, setShowPwd] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();

  if (user) return <Navigate to="/dashboard" replace />;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await login(username.trim(), password);
      toast({ title: "Welcome back", description: "Encrypted session established.", variant: "success" });
      navigate("/dashboard");
    } catch (err: any) {
      toast({
        title: "Authentication failed",
        description: err?.response?.data?.detail ?? "Invalid credentials",
        variant: "error",
      });
    } finally {
      setSubmitting(false);
    }
  }

  function fillAs(role: "admin" | "analyst") {
    if (role === "admin") {
      setUsername("admin");
      setPassword("admin123");
    } else {
      setUsername("analyst");
      setPassword("analyst123");
    }
  }

  return (
    <div className="grid min-h-screen w-full grid-cols-1 lg:grid-cols-2">
      <div className="relative hidden flex-col justify-between overflow-hidden border-r border-border bg-cyber-panel/80 p-12 lg:flex animated-grid">
        <div className="absolute -right-32 -top-32 h-96 w-96 rounded-full bg-cyber-cyan/10 blur-3xl" />
        <div className="absolute -bottom-40 -left-32 h-96 w-96 rounded-full bg-cyber-blue/10 blur-3xl" />

        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-gradient-to-br from-cyber-blue to-cyber-cyan text-white shadow-lg shadow-cyan-500/30">
            <Boxes className="h-6 w-6" />
       </div>
          <div>
            <div className="text-lg font-bold gradient-text">CipherTwin</div>
            <div className="text-xs uppercase tracking-widest text-muted-foreground">
              Autonomous Cyber Defense Framework
         </div>
       </div>
     </div>

        <div className="relative z-10 max-w-md space-y-6">
          <h1 className="text-4xl font-bold leading-tight tracking-tight">
            Explainable <span className="gradient-text">Zero Trust</span><br />
            powered by Digital Twins & Quantum-Inspired Optimization.
         </h1>
          <p className="text-muted-foreground">
            Continuously simulate telemetry, evaluate risk, redirect threats into
            adaptive decoys, and let QAOA-inspired policy tuning keep your
            posture sharp - all in a single SOC cockpit.
         </p>
          <div className="grid grid-cols-2 gap-3">
            <Feature title="Digital Twin" desc="Live enterprise graph." />
            <Feature title="Zero Trust" desc="Per-decision explanations." />
            <Feature title="Adaptive Deception" desc="SSH, DB, Web decoys." />
            <Feature title="QAOA Optimiser" desc="Tune policies nightly." />
       </div>
     </div>

        <div className="text-xs text-muted-foreground">
          CipherTwin Research Prototype - For academic use only.
     </div>
   </div>

      <div className="flex items-center justify-center p-6">
        <Card className="w-full max-w-md glass">
          <CardContent className="space-y-6 p-8">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-cyber-cyan" />
              <span className="text-sm font-medium">Secure Sign-In</span>
         </div>
            <div>
              <h2 className="text-2xl font-bold">Sign in to your console</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Use the demo credentials below or pick a quick-fill role.
             </p>
         </div>

            <form onSubmit={onSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  required
                />
         </div>
              <div className="space-y-1.5">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPwd ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                  />
                  <button
                    type="button"
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground"
                    onClick={() => setShowPwd((v) => !v)}
                    aria-label={showPwd ? "Hide password" : "Show password"}
                  >
                    {showPwd ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
               </button>
             </div>
           </div>

              <Button type="submit" variant="cyber" disabled={submitting} className="w-full">
                {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Authenticate with JWT
            </Button>
         </form>

            <div className="rounded-lg border border-dashed border-border bg-muted/20 p-3 text-xs">
              <div className="mb-2 font-semibold uppercase tracking-wider text-muted-foreground">
                Demo accounts
            </div>
              <div className="grid grid-cols-2 gap-2">
                <Button type="button" variant="outline" size="sm" onClick={() => fillAs("admin")}>
                  admin / admin123
            </Button>
                <Button type="button" variant="outline" size="sm" onClick={() => fillAs("analyst")}>
                  analyst / analyst123
            </Button>
         </div>
       </div>
       </CardContent>
     </Card>
   </div>
 </div>
  );
}

function Feature({ title, desc }: { title: string; desc: string }) {
  return (
    <div className="rounded-lg border border-border bg-card/40 p-3 backdrop-blur-md">
      <div className="text-sm font-semibold text-cyber-cyan">{`${title}`}</div>
      <div className="text-xs text-muted-foreground">{`${desc}`}</div>
  </div>
  );
}
