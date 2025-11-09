/**
 * ChronoGuard Temporal Analytics API
 *
 * Provides methods for temporal pattern analysis and metrics.
 */

import { HttpClient } from './client';
import {
  TemporalPattern,
  TemporalAnalyticsOptions,
  HealthResponse,
  MetricsSummary
} from './types';

/**
 * Analytics and monitoring API client
 */
export class AnalyticsAPI {
  private readonly client: HttpClient;

  constructor(client: HttpClient) {
    this.client = client;
  }

  /**
   * Get temporal analytics for audit access patterns
   *
   * @param options - Time range for analysis
   * @returns Temporal pattern analysis with distributions, anomalies, and compliance score
   *
   * @throws {ValidationError} If time range is invalid
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * const pattern = await client.analytics.getTemporalPattern({
   *   start_time: '2025-01-01T00:00:00Z',
   *   end_time: '2025-01-31T23:59:59Z'
   * });
   *
   * console.log(`Compliance Score: ${pattern.compliance_score}`);
   * console.log(`Peak Hours: ${pattern.peak_hours.join(', ')}`);
   * console.log(`Off-hours Activity: ${pattern.off_hours_activity_percentage}%`);
   * console.log(`Weekend Activity: ${pattern.weekend_activity_percentage}%`);
   *
   * // Analyze hourly distribution
   * Object.entries(pattern.hourly_distribution).forEach(([hour, count]) => {
   *   console.log(`Hour ${hour}: ${count} requests`);
   * });
   *
   * // Check for anomalies
   * pattern.anomalies.forEach(anomaly => {
   *   console.log(`${anomaly.severity}: ${anomaly.description}`);
   * });
   * ```
   */
  async getTemporalPattern(options: TemporalAnalyticsOptions): Promise<TemporalPattern> {
    const startTime = typeof options.start_time === 'string'
      ? options.start_time
      : options.start_time.toISOString();

    const endTime = typeof options.end_time === 'string'
      ? options.end_time
      : options.end_time.toISOString();

    const params = {
      start_time: startTime,
      end_time: endTime
    };

    return this.client.get<TemporalPattern>('/api/v1/audit/analytics', { params });
  }

  /**
   * Get basic health check status
   *
   * @returns Health status response
   *
   * @throws {ChronoGuardError} For API errors
   *
   * @example
   * ```typescript
   * const health = await client.analytics.healthCheck();
   * console.log(`Service: ${health.service} v${health.version}`);
   * console.log(`Status: ${health.status}`);
   * ```
   */
  async healthCheck(): Promise<HealthResponse> {
    return this.client.get<HealthResponse>('/api/v1/health/');
  }

  /**
   * Get readiness check status (includes database connectivity)
   *
   * @returns Readiness status response
   *
   * @throws {ServerError} If database is not available (503)
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * try {
   *   const ready = await client.analytics.readinessCheck();
   *   console.log(`Database: ${ready.database}`);
   * } catch (error) {
   *   console.error('Service not ready:', error.message);
   * }
   * ```
   */
  async readinessCheck(): Promise<HealthResponse> {
    return this.client.get<HealthResponse>('/api/v1/health/ready');
  }

  /**
   * Get system metrics summary for dashboard
   *
   * Requires tenant ID to be set in the client configuration.
   *
   * @returns Metrics summary with counts for agents, policies, and activity
   *
   * @throws {ChronoGuardError} For API errors
   *
   * @example
   * ```typescript
   * const metrics = await client.analytics.getMetrics();
   *
   * console.log(`Total Agents: ${metrics.agents.total}`);
   * console.log(`Active Agents: ${metrics.agents.active}`);
   * console.log(`Suspended Agents: ${metrics.agents.suspended}`);
   * console.log(`Pending Agents: ${metrics.agents.pending}`);
   *
   * console.log(`Total Policies: ${metrics.policies.total}`);
   * console.log(`Active Policies: ${metrics.policies.active}`);
   * ```
   */
  async getMetrics(): Promise<MetricsSummary> {
    return this.client.get<MetricsSummary>('/api/v1/health/metrics');
  }
}
