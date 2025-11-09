/**
 * TypeScript types generated from Python DTOs
 * These types match the backend API responses
 */

// Agent Types
export interface AgentDTO {
  agent_id: string;
  tenant_id: string;
  name: string;
  status: "active" | "suspended" | "pending";
  certificate_fingerprint: string;
  certificate_subject: string;
  certificate_expiry: string;
  policy_ids: string[];
  created_at: string;
  updated_at: string;
  last_seen_at: string | null;
  metadata: Record<string, any>;
  version: number;
}

export interface CreateAgentRequest {
  name: string;
  certificate_pem: string;
  metadata?: Record<string, any>;
}

export interface UpdateAgentRequest {
  name?: string;
  status?: "active" | "suspended" | "pending_activation" | "expired";
  certificate_pem?: string;
  metadata?: Record<string, string>;
}

export interface AgentListResponse {
  agents: AgentDTO[];
  total_count: number;
  page: number;
  page_size: number;
  has_more: boolean;
}

// Policy Types
export interface TimeRangeDTO {
  start_hour: number;
  start_minute: number;
  end_hour: number;
  end_minute: number;
}

export interface TimeRestrictionDTO {
  allowed_days: number[];
  allowed_time_ranges: TimeRangeDTO[];
  timezone: string;
}

export interface RateLimitDTO {
  requests_per_minute: number;
  requests_per_hour: number;
  burst_size: number;
}

export interface RuleConditionDTO {
  field: string;
  operator: string;
  value: string;
}

export interface PolicyRuleDTO {
  rule_id: string;
  name: string;
  priority: number;
  action: "allow" | "deny" | "rate_limit";
  conditions: RuleConditionDTO[];
  time_restrictions: TimeRestrictionDTO | null;
  rate_limit: RateLimitDTO | null;
  is_active: boolean;
}

export interface PolicyDTO {
  policy_id: string;
  tenant_id: string;
  name: string;
  description: string;
  rules: PolicyRuleDTO[];
  time_restrictions: any | null;
  rate_limits: any | null;
  priority: number;
  status: "active" | "inactive";
  allowed_domains: string[];
  blocked_domains: string[];
  created_at: string;
  updated_at: string;
  created_by: string;
  version: number;
  metadata: Record<string, any>;
}

export interface CreatePolicyRequest {
  name: string;
  description: string;
  priority?: number;
  allowed_domains?: string[];
  blocked_domains?: string[];
  metadata?: Record<string, string>;
}

export interface UpdatePolicyRequest {
  name?: string;
  description?: string;
  priority?: number;
  allowed_domains?: string[];
  blocked_domains?: string[];
  default_action?: "allow" | "deny";
  is_active?: boolean;
}

export interface PolicyListResponse {
  policies: PolicyDTO[];
  total_count: number;
  page: number;
  page_size: number;
  has_more: boolean;
}

// Audit Types
export interface TimedAccessContextDTO {
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

export interface AuditEntryDTO {
  entry_id: string;
  tenant_id: string;
  agent_id: string;
  timestamp: string;
  timestamp_nanos: number;
  domain: string;
  decision: string;
  reason: string;
  policy_id: string | null;
  rule_id: string | null;
  request_method: string;
  request_path: string;
  user_agent: string | null;
  source_ip: string | null;
  response_status: number | null;
  response_size_bytes: number | null;
  processing_time_ms: number | null;
  timed_access_metadata: TimedAccessContextDTO;
  previous_hash: string;
  current_hash: string;
  sequence_number: number;
  metadata: Record<string, string>;
}

export interface AuditQueryRequest {
  tenant_id?: string;
  agent_id?: string;
  domain?: string;
  decision?: string;
  start_time?: string;
  end_time?: string;
  page?: number;
  page_size?: number;
}

export interface AuditListResponse {
  entries: AuditEntryDTO[];
  total_count: number;
  page: number;
  page_size: number;
  has_more: boolean;
}

export interface AuditExportRequest {
  tenant_id: string;
  start_time: string;
  end_time: string;
  format: "csv" | "json";
  include_metadata?: boolean;
  pretty_json?: boolean;
}

export interface TemporalPatternDTO {
  tenant_id: string;
  start_time: string;
  end_time: string;
  hourly_distribution: Record<number, number>;
  daily_distribution: Record<string, number>;
  peak_hours: number[];
  off_hours_activity_percentage: number;
  weekend_activity_percentage: number;
  top_domains: Array<{ domain: string; count: number }>;
  anomalies: Array<{
    type: string;
    severity: string;
    description: string;
    [key: string]: string;
  }>;
  compliance_score: number;
}

// Metrics Types
export interface MetricsSummaryResponse {
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
  recent_activity: Record<string, number> | null;
}

// Health Types
export interface HealthResponse {
  status: string;
  timestamp: string;
  service: string;
  version: string;
  database?: string;
}

// Auth Types
export interface LoginResponse {
  access_token: string;
  token_type: string;
  tenant_id: string;
  user_id: string;
  expires_in: number;
}
