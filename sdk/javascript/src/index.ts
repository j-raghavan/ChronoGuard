/**
 * ChronoGuard SDK
 *
 * Official TypeScript/JavaScript SDK for ChronoGuard - Temporal Access Control System
 *
 * @packageDocumentation
 */

import { HttpClient } from './client';
import { AgentAPI } from './agents';
import { PolicyAPI } from './policies';
import { AuditAPI } from './audit';
import { AnalyticsAPI } from './analytics';
import { ChronoGuardConfig, UUID } from './types';

/**
 * Main ChronoGuard SDK client
 *
 * Provides a unified interface for all ChronoGuard API operations.
 *
 * @example
 * Basic usage:
 * ```typescript
 * import { ChronoGuard } from '@chronoguard/sdk';
 *
 * const client = new ChronoGuard({
 *   apiUrl: 'http://localhost:8000',
 *   tenantId: '550e8400-e29b-41d4-a716-446655440001',
 *   userId: '550e8400-e29b-41d4-a716-446655440002'
 * });
 *
 * // Create an agent
 * const agent = await client.agents.create({
 *   name: 'qa-agent-prod-01',
 *   certificate_pem: certificatePem,
 *   metadata: { environment: 'production' }
 * });
 *
 * // Create a policy
 * const policy = await client.policies.create({
 *   name: 'production-qa-policy',
 *   description: 'Access policy for production QA agents',
 *   allowed_domains: ['example.com']
 * });
 *
 * // Query audit logs
 * const auditLogs = await client.audit.query({
 *   agent_id: agent.agent_id,
 *   start_time: '2025-01-01T00:00:00Z',
 *   end_time: '2025-01-31T23:59:59Z'
 * });
 *
 * // Get temporal analytics
 * const analytics = await client.analytics.getTemporalPattern({
 *   start_time: new Date('2025-01-01'),
 *   end_time: new Date('2025-01-31')
 * });
 * ```
 *
 * @example
 * With debug logging:
 * ```typescript
 * const client = new ChronoGuard({
 *   apiUrl: 'http://localhost:8000',
 *   debug: true
 * });
 * ```
 */
export class ChronoGuard {
  /**
   * Agent management API
   */
  public readonly agents: AgentAPI;

  /**
   * Policy management API
   */
  public readonly policies: PolicyAPI;

  /**
   * Audit log API
   */
  public readonly audit: AuditAPI;

  /**
   * Analytics and monitoring API
   */
  public readonly analytics: AnalyticsAPI;

  /**
   * Underlying HTTP client
   */
  private readonly httpClient: HttpClient;

  /**
   * Create a new ChronoGuard SDK client
   *
   * @param config - SDK configuration
   *
   * @throws {ConfigurationError} If configuration is invalid
   */
  constructor(config: ChronoGuardConfig) {
    this.httpClient = new HttpClient(config);
    this.agents = new AgentAPI(this.httpClient);
    this.policies = new PolicyAPI(this.httpClient);
    this.audit = new AuditAPI(this.httpClient);
    this.analytics = new AnalyticsAPI(this.httpClient);
  }

  /**
   * Update tenant ID for subsequent requests
   *
   * @param tenantId - Tenant identifier
   */
  setTenantId(tenantId: UUID): void {
    this.httpClient.setTenantId(tenantId);
  }

  /**
   * Update user ID for subsequent requests
   *
   * @param userId - User identifier
   */
  setUserId(userId: UUID): void {
    this.httpClient.setUserId(userId);
  }

  /**
   * Get current tenant ID
   */
  getTenantId(): UUID | undefined {
    return this.httpClient.getTenantId();
  }

  /**
   * Get current user ID
   */
  getUserId(): UUID | undefined {
    return this.httpClient.getUserId();
  }

  /**
   * Get API base URL
   */
  getBaseUrl(): string {
    return this.httpClient.getBaseUrl();
  }
}

// Export all types and error classes for external use
export * from './types';
export * from './errors';
export { AgentAPI } from './agents';
export { PolicyAPI } from './policies';
export { AuditAPI } from './audit';
export { AnalyticsAPI } from './analytics';

// Default export
export default ChronoGuard;
