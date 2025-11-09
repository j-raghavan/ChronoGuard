import { describe, it, expect } from "vitest";
import type {
  AgentDTO,
  PolicyDTO,
  AuditEntryDTO,
  TemporalPatternDTO,
  MetricsSummaryResponse,
  HealthResponse,
} from "./api";

describe("API Types", () => {
  it("should define AgentDTO type", () => {
    const agent: AgentDTO = {
      agent_id: "123",
      tenant_id: "456",
      name: "test",
      status: "active",
      certificate_pem: "cert",
      certificate_fingerprint: "fp",
      certificate_serial: "serial",
      certificate_subject: "subj",
      certificate_issuer: "issuer",
      certificate_not_before: "2025-01-01T00:00:00Z",
      certificate_not_after: "2026-01-01T00:00:00Z",
      created_at: "2025-01-01T00:00:00Z",
      updated_at: "2025-01-01T00:00:00Z",
      suspended_at: null,
      suspended_by: null,
      metadata: {},
    };
    expect(agent.agent_id).toBe("123");
  });

  it("should define TemporalPatternDTO type", () => {
    const pattern: TemporalPatternDTO = {
      tenant_id: "123",
      start_time: "2025-01-01T00:00:00Z",
      end_time: "2025-01-31T23:59:59Z",
      hourly_distribution: {},
      daily_distribution: {},
      peak_hours: [],
      off_hours_activity_percentage: 0,
      weekend_activity_percentage: 0,
      top_domains: [],
      anomalies: [],
      compliance_score: 0,
    };
    expect(pattern.tenant_id).toBe("123");
  });

  it("should define MetricsSummaryResponse type", () => {
    const metrics: MetricsSummaryResponse = {
      timestamp: new Date().toISOString(),
      agents: { total: 5, active: 3, suspended: 1, pending: 1 },
      policies: { total: 2, active: 1 },
      recent_activity: null,
    };
    expect(metrics.agents.total).toBe(5);
  });
});
