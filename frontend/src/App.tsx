import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { ToasterProvider } from "@/components/Toaster";
import { DashboardLayout } from "@/components/Layout/DashboardLayout";

import LoginPage from "@/pages/LoginPage";
import OverviewPage from "@/pages/OverviewPage";
import NetworkTwinPage from "@/pages/NetworkTwinPage";
import TelemetryPage from "@/pages/TelemetryPage";
import AccessRequestsPage from "@/pages/AccessRequestsPage";
import RiskAnalyticsPage from "@/pages/RiskAnalyticsPage";
import ThreatsPage from "@/pages/ThreatsPage";
import DeceptionPage from "@/pages/DeceptionPage";
import OptimizationPage from "@/pages/OptimizationPage";
import PoliciesPage from "@/pages/PoliciesPage";
import AuditPage from "@/pages/AuditPage";
import ExplainerPage from "@/pages/ExplainerPage";
import SettingsPage from "@/pages/SettingsPage";

import type { ReactNode } from "react";

function Protected({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center text-muted-foreground">
        <div className="animate-pulse2 text-sm uppercase tracking-widest">
          Initializing CipherTwin SOC...
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function AppRoutes() {
  return (
    <Routes>
      {/* Login */}
      <Route path="/login" element={<LoginPage />} />

      {/* Protected application */}
      <Route
        path="/"
        element={
          <Protected>
            <DashboardLayout />
          </Protected>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />

        <Route path="dashboard" element={<OverviewPage />} />
        <Route path="twin" element={<NetworkTwinPage />} />
        <Route path="telemetry" element={<TelemetryPage />} />
        <Route path="access-requests" element={<AccessRequestsPage />} />
        <Route path="risk" element={<RiskAnalyticsPage />} />
        <Route path="threats" element={<ThreatsPage />} />
        <Route path="deception" element={<DeceptionPage />} />
        <Route path="optimization" element={<OptimizationPage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="explainer" element={<ExplainerPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>

      {/* Unknown routes */}
      <Route
        path="*"
        element={<Navigate to="/dashboard" replace />}
      />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ToasterProvider>
        <AppRoutes />
      </ToasterProvider>
    </AuthProvider>
  );
}
