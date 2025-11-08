import { useMetrics, useAuditAnalytics } from '@/hooks/useApi';
import { subDays } from 'date-fns';
import { Shield, FileText, Activity, TrendingUp } from 'lucide-react';

export function Dashboard() {
  const { data: metrics, isLoading: metricsLoading } = useMetrics();

  // Get analytics for the last 7 days
  const endTime = new Date();
  const startTime = subDays(endTime, 7);
  const { data: analytics, isLoading: analyticsLoading } = useAuditAnalytics(
    startTime.toISOString(),
    endTime.toISOString()
  );

  if (metricsLoading || analyticsLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  const stats = [
    {
      name: 'Total Agents',
      value: metrics?.agents.total || 0,
      icon: Shield,
      change: `${metrics?.agents.active || 0} active`,
      changeType: 'positive',
    },
    {
      name: 'Total Policies',
      value: metrics?.policies.total || 0,
      icon: FileText,
      change: `${metrics?.policies.active || 0} active`,
      changeType: 'positive',
    },
    {
      name: 'Compliance Score',
      value: `${analytics?.compliance_score.toFixed(1) || 0}%`,
      icon: TrendingUp,
      change: 'Last 7 days',
      changeType: 'neutral',
    },
    {
      name: 'Peak Activity Hour',
      value: analytics?.peak_hours[0] || '-',
      icon: Activity,
      change: 'Most active time',
      changeType: 'neutral',
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
        <p className="text-muted-foreground">
          Overview of your ChronoGuard system
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <div
              key={stat.name}
              className="rounded-lg border border-border bg-card p-6"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">
                    {stat.name}
                  </p>
                  <p className="text-2xl font-bold mt-2">{stat.value}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {stat.change}
                  </p>
                </div>
                <Icon className="h-8 w-8 text-muted-foreground" />
              </div>
            </div>
          );
        })}
      </div>

      {/* Anomalies Section */}
      {analytics && analytics.anomalies.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-6">
          <h3 className="text-lg font-semibold mb-4">Recent Anomalies</h3>
          <div className="space-y-3">
            {analytics.anomalies.slice(0, 5).map((anomaly, idx) => (
              <div
                key={idx}
                className="flex items-start gap-3 p-3 rounded-md bg-accent"
              >
                <div
                  className={`h-2 w-2 mt-2 rounded-full ${
                    anomaly.severity === 'high'
                      ? 'bg-red-500'
                      : anomaly.severity === 'medium'
                      ? 'bg-yellow-500'
                      : 'bg-blue-500'
                  }`}
                />
                <div>
                  <p className="text-sm font-medium">{anomaly.type}</p>
                  <p className="text-xs text-muted-foreground">
                    {anomaly.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top Domains */}
      {analytics && analytics.top_domains.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-6">
          <h3 className="text-lg font-semibold mb-4">Top Accessed Domains</h3>
          <div className="space-y-3">
            {analytics.top_domains.slice(0, 5).map((domain, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 rounded-md bg-accent"
              >
                <span className="text-sm font-medium">{domain.domain}</span>
                <span className="text-sm text-muted-foreground">
                  {domain.count} requests
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
