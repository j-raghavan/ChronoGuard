/**
 * ChronoGuard SDK Type Definitions
 *
 * Complete TypeScript type definitions for the ChronoGuard API.
 */

/**
 * Common types
 */
export type UUID = string;

/**
 * Agent status enumeration
 */
export enum AgentStatus {
  ACTIVE = 'active',
  SUSPENDED = 'suspended',
  PENDING_ACTIVATION = 'pending_activation',
  REVOKED = 'revoked'
}

/**
 * Policy status enumeration
 */
export enum PolicyStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  DRAFT = 'draft'
}

/**
 * Access decision enumeration
 */
export enum AccessDecision {
  ALLOW = 'allow',
  DENY = 'deny',
  BLOCK = 'block',
  RATE_LIMITED = 'rate_limited',
  TIME_RESTRICTED = 'time_restricted',
  POLICY_VIOLATION = 'policy_violation'
}

/**
 * Export format enumeration
 */
export enum ExportFormat {
  CSV = 'csv',
  JSON = 'json'
}

/**
 * Agent entity
 */
export interface Agent {
  agent_id: UUID;
  tenant_id: UUID;
  name: string;
  status: AgentStatus | string;
  certificate_fingerprint: string | null;
  certificate_subject: string | null;
  certificate_expiry: string | null;
  policy_ids: UUID[];
  created_at: string;
  updated_at: string;
  last_seen_at: string | null;
  metadata: Record<string, unknown>;
  version: number;
}

/**
 * Create agent request
 */
export interface CreateAgentRequest {
  name: string;
  certificate_pem: string;
  metadata?: Record<string, unknown>;
}

/**
 * Update agent request
 */
export interface UpdateAgentRequest {
  name?: string;
  certificate_pem?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Agent list response
 */
export interface AgentListResponse {
  agents: Agent[];
  total_count: number;
  page: number;
  page_size: number;
}

/**
 * Rule condition
 */
export interface RuleCondition {
  field: string;
  operator: string;
  value: string;
}

/**
 * Policy rule
 */
export interface PolicyRule {
  rule_id: UUID;
  name: string;
  description: string;
  conditions: RuleCondition[];
  action: string;
  priority: number;
  enabled: boolean;
  metadata: Record<string, string>;
}

/**
 * Time range
 */
export interface TimeRange {
  start_hour: number;
  start_minute: number;
  end_hour: number;
  end_minute: number;
}

/**
 * Time restriction
 */
export interface TimeRestriction {
  allowed_time_ranges: TimeRange[];
  allowed_days_of_week: number[];
  timezone: string;
  enabled: boolean;
}

/**
 * Rate limit
 */
export interface RateLimit {
  requests_per_minute: number;
  requests_per_hour: number;
  requests_per_day: number;
  burst_limit: number;
  enabled: boolean;
}

/**
 * Policy entity
 */
export interface Policy {
  policy_id: UUID;
  tenant_id: UUID;
  name: string;
  description: string;
  rules: PolicyRule[];
  time_restrictions: TimeRestriction | null;
  rate_limits: RateLimit | null;
  priority: number;
  status: PolicyStatus | string;
  allowed_domains: string[];
  blocked_domains: string[];
  created_at: string;
  updated_at: string;
  created_by: UUID;
  version: number;
  metadata: Record<string, string>;
}

/**
 * Create policy request
 */
export interface CreatePolicyRequest {
  name: string;
  description: string;
  priority?: number;
  allowed_domains?: string[];
  blocked_domains?: string[];
  metadata?: Record<string, string>;
}

/**
 * Update policy request
 */
export interface UpdatePolicyRequest {
  name?: string;
  description?: string;
  priority?: number;
  allowed_domains?: string[];
  blocked_domains?: string[];
  metadata?: Record<string, string>;
}

/**
 * Policy list response
 */
export interface PolicyListResponse {
  policies: Policy[];
  total_count: number;
  page: number;
  page_size: number;
}

/**
 * Timed access context
 */
export interface TimedAccessContext {
  request_timestamp: string;
  processing_timestamp: string;
  timezone_offset: number;
  day_of_week: number;
  hour_of_day: number;
  is_business_hours: boolean;
  is_weekend: boolean;
  week_of_year: number;
  month_of_year: number;
  quarter_of_year: number;
}

/**
 * Audit entry
 */
export interface AuditEntry {
  entry_id: UUID;
  tenant_id: UUID;
  agent_id: UUID;
  timestamp: string;
  timestamp_nanos: number;
  domain: string;
  decision: AccessDecision | string;
  reason: string;
  policy_id: UUID | null;
  rule_id: UUID | null;
  request_method: string;
  request_path: string;
  user_agent: string | null;
  source_ip: string | null;
  response_status: number | null;
  response_size_bytes: number | null;
  processing_time_ms: number | null;
  timed_access_metadata: TimedAccessContext;
  previous_hash: string;
  current_hash: string;
  sequence_number: number;
  metadata: Record<string, string>;
}

/**
 * Audit query request
 */
export interface AuditQueryRequest {
  tenant_id?: UUID;
  agent_id?: UUID;
  domain?: string;
  decision?: AccessDecision | string;
  start_time?: string;
  end_time?: string;
  page?: number;
  page_size?: number;
}

/**
 * Audit list response
 */
export interface AuditListResponse {
  entries: AuditEntry[];
  total_count: number;
  page: number;
  page_size: number;
  has_more: boolean;
}

/**
 * Audit export request
 */
export interface AuditExportRequest {
  tenant_id: UUID;
  start_time: string;
  end_time: string;
  format?: ExportFormat | string;
  include_metadata?: boolean;
  pretty_json?: boolean;
}

/**
 * Domain count for analytics
 */
export interface DomainCount {
  domain: string;
  count: number;
}

/**
 * Temporal anomaly
 */
export interface TemporalAnomaly {
  type: string;
  severity: string;
  description: string;
  timestamp?: string;
  details?: Record<string, unknown>;
}

/**
 * Temporal pattern analysis
 */
export interface TemporalPattern {
  tenant_id: UUID;
  start_time: string;
  end_time: string;
  hourly_distribution: Record<number, number>;
  daily_distribution: Record<string, number>;
  peak_hours: number[];
  off_hours_activity_percentage: number;
  weekend_activity_percentage: number;
  top_domains: DomainCount[];
  anomalies: TemporalAnomaly[];
  compliance_score: number;
}

/**
 * Health check response
 */
export interface HealthResponse {
  status: string;
  timestamp: string;
  service: string;
  version: string;
  database?: string;
}

/**
 * Metrics summary response
 */
export interface MetricsSummary {
  timestamp: string;
  agents: {
    total: number;
    active: number;
    suspended: number;
    pending: number;
  };
  policies: {
    total: number;
    active: number;
  };
  recent_activity?: Record<string, number>;
}

/**
 * SDK Configuration
 */
export interface ChronoGuardConfig {
  /**
   * Base URL for the ChronoGuard API
   * @example 'http://localhost:8000'
   */
  apiUrl: string;

  /**
   * Tenant ID for multi-tenant requests
   */
  tenantId?: UUID;

  /**
   * User ID for operations requiring user context
   */
  userId?: UUID;

  /**
   * Request timeout in milliseconds
   * @default 30000
   */
  timeout?: number;

  /**
   * Custom headers to include in all requests
   */
  headers?: Record<string, string>;

  /**
   * Enable debug logging
   * @default false
   */
  debug?: boolean;
}

/**
 * Pagination options
 */
export interface PaginationOptions {
  page?: number;
  page_size?: number;
}

/**
 * Agent list options
 */
export interface AgentListOptions extends PaginationOptions {
  status_filter?: AgentStatus | string;
}

/**
 * Policy list options
 */
export interface PolicyListOptions extends PaginationOptions {
  status_filter?: PolicyStatus | string;
}

/**
 * Temporal analytics query options
 */
export interface TemporalAnalyticsOptions {
  start_time: string | Date;
  end_time: string | Date;
}
