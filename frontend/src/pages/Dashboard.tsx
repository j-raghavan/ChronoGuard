import { useMetrics, useAuditAnalytics } from "@/hooks/useApi";
import { subDays } from "date-fns";
import { Shield, FileText, Activity, TrendingUp, AlertTriangle, Globe } from "lucide-react";
import { useMemo, useState, useEffect } from "react";
import { SeedDataPrompt } from "@/components/SeedDataPrompt";

export function Dashboard() {
  const [showSeedPrompt, setShowSeedPrompt] = useState(false);
  const { data: metrics, isLoading: metricsLoading, refetch: refetchMetrics } = useMetrics();

  // Get analytics for the last 7 days (memoized to prevent infinite loop)
  const { startTime, endTime } = useMemo(() => {
    const end = new Date();
    const start = subDays(end, 7);
    return {
      startTime: start.toISOString(),
      endTime: end.toISOString(),
    };
  }, []); // Empty deps array - only calculate once on mount

  const { data: analytics, isLoading: analyticsLoading, refetch: refetchAnalytics } = useAuditAnalytics(
    startTime,
    endTime,
  );

  // Check if database is empty (no agents or policies)
  const isDatabaseEmpty = metrics && metrics.agents.total === 0 && metrics.policies.total === 0;

  // Show seed prompt when database is empty
  useEffect(() => {
    if (isDatabaseEmpty && !localStorage.getItem("seedPromptDismissed")) {
      setShowSeedPrompt(true);
    }
  }, [isDatabaseEmpty]);

  const handleSeedDatabase = async () => {
    try {
      // Call the backend seed endpoint
      const response = await fetch("http://localhost:8000/api/v1/internal/seed", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Tenant-ID": localStorage.getItem("tenantId") || "",
        },
      });

      if (response.ok) {
        // Refresh metrics and analytics
        await refetchMetrics();
        await refetchAnalytics();
        setShowSeedPrompt(false);
      } else {
        console.error("Failed to seed database");
      }
    } catch (error) {
      console.error("Error seeding database:", error);
    }
  };

  const handleDismissSeedPrompt = () => {
    localStorage.setItem("seedPromptDismissed", "true");
    setShowSeedPrompt(false);
  };

  if (metricsLoading || analyticsLoading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "24rem" }}>
        <div style={{ color: "hsl(var(--muted-foreground))", fontSize: "1.125rem" }}>
          Loading dashboard...
        </div>
      </div>
    );
  }

  const stats = [
    {
      name: "Total Agents",
      value: metrics?.agents?.total ?? 0,
      icon: Shield,
      change: `${metrics?.agents?.active ?? 0} active`,
      gradient: "linear-gradient(to right, #C693F8, #A85FF4)"
    },
    {
      name: "Total Policies",
      value: metrics?.policies?.total ?? 0,
      icon: FileText,
      change: `${metrics?.policies?.active ?? 0} active`,
      gradient: "linear-gradient(to right, #6AA4E3, #6564E7)"
    },
    {
      name: "Compliance Score",
      value: `${(analytics?.compliance_score ?? 0).toFixed(1)}%`,
      icon: TrendingUp,
      change: "Last 7 days",
      gradient: "linear-gradient(to right, #FDB786, #FE8A93)"
    },
    {
      name: "Peak Activity",
      value: analytics?.peak_hours?.[0]?.toString() ?? "-",
      icon: Activity,
      change: "Most active hour",
      gradient: "linear-gradient(to right, #42CDF8, #6AA4E3)"
    },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem", width: "100%", maxWidth: "100%" }}>
      {/* Seed Data Prompt */}
      {showSeedPrompt && (
        <SeedDataPrompt
          onSeed={handleSeedDatabase}
          onDismiss={handleDismissSeedPrompt}
        />
      )}

      {/* Page Header */}
      <div style={{ width: "100%" }}>
        <h2 style={{ fontSize: "1.875rem", fontWeight: "bold", letterSpacing: "-0.025em", color: "hsl(var(--foreground))" }}>
          Dashboard
        </h2>
        <p style={{ marginTop: "0.5rem", fontSize: "1rem", color: "hsl(var(--muted-foreground))" }}>
          Welcome back! Here's what's happening with your ChronoGuard system.
        </p>
      </div>

      {/* Stats Grid */}
      <div style={{
        display: "grid",
        gap: "1.5rem",
        gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
        width: "100%"
      }}>
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <div
              key={stat.name}
              style={{
                background: stat.gradient,
                minHeight: "180px",
                display: "flex",
                flexDirection: "column",
                justifyContent: "space-between",
                borderRadius: "12px",
                padding: "1.5rem",
                position: "relative",
                overflow: "hidden",
                boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)"
              }}
            >
              {/* Decorative circles */}
              <div
                style={{
                  position: "absolute",
                  width: "140px",
                  height: "140px",
                  backgroundColor: "rgba(255, 255, 255, 0.15)",
                  borderRadius: "50%",
                  top: "-50px",
                  left: "-50px"
                }}
              />
              <div
                style={{
                  position: "absolute",
                  width: "140px",
                  height: "140px",
                  backgroundColor: "rgba(255, 255, 255, 0.15)",
                  borderRadius: "50%",
                  bottom: "-50px",
                  right: "-50px"
                }}
              />

              <div style={{ position: "relative", zIndex: 10 }}>
                <Icon style={{ height: "2rem", width: "2rem", color: "white", marginBottom: "1rem", opacity: 0.9 }} />
                <p style={{ color: "white", fontSize: "0.875rem", marginBottom: "0.5rem", fontWeight: 500, opacity: 0.9 }}>
                  {stat.name}
                </p>
                <h2 style={{ color: "white", fontSize: "1.875rem", fontWeight: "bold" }}>
                  {stat.value}
                </h2>
              </div>
              <p style={{ color: "white", fontSize: "0.875rem", position: "relative", zIndex: 10, opacity: 0.9, fontWeight: 500 }}>
                {stat.change}
              </p>
            </div>
          );
        })}
      </div>

      {/* Two Column Layout */}
      <div style={{
        display: "grid",
        gap: "1.5rem",
        gridTemplateColumns: "repeat(auto-fit, minmax(400px, 1fr))",
        width: "100%"
      }}>
        {/* Anomalies Section */}
        <div
          style={{
            backgroundColor: "white",
            borderRadius: "12px",
            padding: "1.5rem",
            boxShadow: "var(--shadow)",
            border: "1px solid hsl(var(--border))"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.5rem" }}>
            <h3 style={{ fontSize: "1.125rem", fontWeight: 600, color: "hsl(var(--foreground))" }}>
              Recent Anomalies
            </h3>
            <AlertTriangle style={{ height: "1.25rem", width: "1.25rem", color: "hsl(var(--warning))" }} />
          </div>
          {analytics && analytics.anomalies && analytics.anomalies.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {analytics.anomalies.slice(0, 5).map((anomaly, idx) => (
                <div
                  key={idx}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: "0.75rem",
                    padding: "0.75rem",
                    borderRadius: "0.5rem",
                    backgroundColor: "hsl(var(--muted))"
                  }}
                >
                  <div
                    style={{
                      height: "0.5rem",
                      width: "0.5rem",
                      marginTop: "0.5rem",
                      borderRadius: "50%",
                      flexShrink: 0,
                      backgroundColor: anomaly.severity === "high"
                        ? "hsl(var(--danger))"
                        : anomaly.severity === "medium"
                        ? "hsl(var(--warning))"
                        : "hsl(var(--primary))"
                    }}
                  />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: "0.875rem", fontWeight: 500, color: "hsl(var(--foreground))" }}>
                      {anomaly.type}
                    </p>
                    <p style={{ fontSize: "0.75rem", marginTop: "0.125rem", color: "hsl(var(--muted-foreground))" }}>
                      {anomaly.description}
                    </p>
                  </div>
                  <span
                    style={{
                      fontSize: "0.75rem",
                      fontWeight: 500,
                      padding: "0.25rem 0.5rem",
                      borderRadius: "0.25rem",
                      backgroundColor: anomaly.severity === "high"
                        ? "rgba(239, 68, 68, 0.1)"
                        : anomaly.severity === "medium"
                        ? "rgba(245, 158, 11, 0.1)"
                        : "rgba(59, 130, 246, 0.1)",
                      color: anomaly.severity === "high"
                        ? "#EF4444"
                        : anomaly.severity === "medium"
                        ? "#F59E0B"
                        : "#3B82F6"
                    }}
                  >
                    {anomaly.severity}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ textAlign: "center", padding: "3rem 0" }}>
              <p style={{ fontSize: "0.875rem", color: "hsl(var(--muted-foreground))" }}>
                No anomalies detected in the last 7 days
              </p>
            </div>
          )}
        </div>

        {/* Top Domains */}
        <div
          style={{
            backgroundColor: "white",
            borderRadius: "12px",
            padding: "1.5rem",
            boxShadow: "var(--shadow)",
            border: "1px solid hsl(var(--border))"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1rem" }}>
            <h3 style={{ fontSize: "1.125rem", fontWeight: 600, color: "hsl(var(--foreground))" }}>
              Top Accessed Domains
            </h3>
            <Globe style={{ height: "1.25rem", width: "1.25rem", color: "hsl(var(--secondary))" }} />
          </div>
          {analytics && analytics.top_domains && analytics.top_domains.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {analytics.top_domains.slice(0, 5).map((domain, idx) => (
                <div
                  key={idx}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "0.75rem",
                    borderRadius: "0.5rem",
                    backgroundColor: "hsl(var(--muted))"
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        width: "2rem",
                        height: "2rem",
                        borderRadius: "0.5rem",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontWeight: 600,
                        color: "white",
                        fontSize: "0.875rem",
                        flexShrink: 0,
                        background: `linear-gradient(135deg, hsl(var(--primary)) 0%, hsl(var(--accent)) 100%)`
                      }}
                    >
                      {idx + 1}
                    </div>
                    <span style={{ fontSize: "0.875rem", fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "hsl(var(--foreground))" }}>
                      {domain.domain}
                    </span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexShrink: 0 }}>
                    <span style={{ fontSize: "0.875rem", fontWeight: 600, color: "hsl(var(--foreground))" }}>
                      {domain.count}
                    </span>
                    <span style={{ fontSize: "0.75rem", color: "hsl(var(--muted-foreground))" }}>
                      requests
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ textAlign: "center", padding: "2rem 0" }}>
              <p style={{ fontSize: "0.875rem", color: "hsl(var(--muted-foreground))" }}>
                No domain access data available
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Activity Overview */}
      <div
        style={{
          backgroundColor: "white",
          borderRadius: "12px",
          padding: "1.5rem",
          boxShadow: "var(--shadow)",
          border: "1px solid hsl(var(--border))",
          width: "100%"
        }}
      >
        <h3 style={{ fontSize: "1.125rem", fontWeight: 600, marginBottom: "1rem", color: "hsl(var(--foreground))" }}>
          System Activity
        </h3>
        <div style={{
          display: "grid",
          gap: "1rem",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))"
        }}>
          <div style={{ padding: "1rem", borderRadius: "0.5rem", backgroundColor: "hsl(var(--muted))" }}>
            <p style={{ fontSize: "0.875rem", fontWeight: 500, color: "hsl(var(--muted-foreground))" }}>
              Total Requests
            </p>
            <p style={{ fontSize: "1.5rem", fontWeight: "bold", marginTop: "0.25rem", color: "hsl(var(--foreground))" }}>
              {analytics?.top_domains?.reduce((sum, d) => sum + d.count, 0) ?? 0}
            </p>
          </div>
          <div style={{ padding: "1rem", borderRadius: "0.5rem", backgroundColor: "hsl(var(--muted))" }}>
            <p style={{ fontSize: "0.875rem", fontWeight: 500, color: "hsl(var(--muted-foreground))" }}>
              Peak Hour
            </p>
            <p style={{ fontSize: "1.5rem", fontWeight: "bold", marginTop: "0.25rem", color: "hsl(var(--foreground))" }}>
              {analytics?.peak_hours?.[0]?.toString() ?? "-"}
            </p>
          </div>
          <div style={{ padding: "1rem", borderRadius: "0.5rem", backgroundColor: "hsl(var(--muted))" }}>
            <p style={{ fontSize: "0.875rem", fontWeight: 500, color: "hsl(var(--muted-foreground))" }}>
              Anomaly Count
            </p>
            <p style={{ fontSize: "1.5rem", fontWeight: "bold", marginTop: "0.25rem", color: "hsl(var(--foreground))" }}>
              {analytics?.anomalies?.length ?? 0}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
