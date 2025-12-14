/**
 * Mock API client for Zero-Install Demo
 * Simulates the backend with in-memory data and live traffic generation
 */

import { v4 as uuidv4 } from 'uuid';
import type {
  AgentDTO,
  AgentListResponse,
  CreateAgentRequest,
  UpdateAgentRequest,
  PolicyDTO,
  PolicyListResponse,
  CreatePolicyRequest,
  UpdatePolicyRequest,
  AuditEntryDTO,
  AuditListResponse,
  AuditQueryRequest,
  TemporalPatternDTO,
  MetricsSummaryResponse,

} from "@/types/api";

// --- Mock Data Store ---

class MockDataStore {
  private agents: AgentDTO[] = [];
  private policies: PolicyDTO[] = [];
  private auditEntries: AuditEntryDTO[] = [];
  private tenantId = "demo-tenant-id";
  private userId = "demo-user-id";

  constructor() {
    this.initializeData();
    // We don't start the interval in the constructor in node/build context as it keeps process alive
    // Ideally this is only called when needed, but for simplicity:
    if (typeof window !== 'undefined') {
        this.startTrafficGenerator();
    }
  }

  private initializeData() {
    // initial policy
    const defaultPolicy: PolicyDTO = {
      policy_id: uuidv4(),
      tenant_id: this.tenantId,
      name: "Standard Research",
      description: "Allow access to standard research domains",
      rules: [],
      time_restrictions: null,
      rate_limits: null,
      priority: 100,
      status: "active",
      allowed_domains: ["google.com", "wikipedia.org", "arxiv.org", "github.com"],
      blocked_domains: ["facebook.com", "twitter.com"],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      created_by: "system",
      version: 1,
      metadata: { demo: true },
    };
    this.policies.push(defaultPolicy);

    // initial agent
    const defaultAgent: AgentDTO = {
      agent_id: uuidv4(),
      tenant_id: this.tenantId,
      name: "Research-Bot-Alpha",
      status: "active",
      certificate_fingerprint: "sha256:demo_fingerprint_123456",
      certificate_subject: "CN=Research-Bot-Alpha",
      certificate_expiry: new Date(Date.now() + 86400000 * 30).toISOString(), // 30 days
      policy_ids: [defaultPolicy.policy_id],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
      metadata: { environment: "demo" },
      version: 1,
    };
    this.agents.push(defaultAgent);
  }

  private startTrafficGenerator() {
    // Generate a new audit entry every 2-5 seconds
    setInterval(() => {
      this.generateAuditEntry();
    }, 3000);
  }

  private generateAuditEntry() {
    const isAllowed = Math.random() > 0.2; // 80% allowed
    const domains = ["google.com", "github.com", "stackoverflow.com", "reddit.com", "malware.site"];
    const domain = domains[Math.floor(Math.random() * domains.length)];
    const agent = this.agents[0]; // use the first agent

    const entry: AuditEntryDTO = {
      entry_id: uuidv4(),
      tenant_id: this.tenantId,
      agent_id: agent ? agent.agent_id : "unknown",
      timestamp: new Date().toISOString(),
      timestamp_nanos: Date.now() * 1000000,
      domain: domain,
      decision: isAllowed ? "allow" : "deny",
      reason: isAllowed ? "Policy allowed" : "Policy denied",
      policy_id: this.policies[0]?.policy_id || null,
      rule_id: null,
      request_method: "GET",
      request_path: "/",
      user_agent: "Mozilla/5.0 Chrome/90.0",
      source_ip: "10.0.0.1",
      response_status: isAllowed ? 200 : 403,
      response_size_bytes: Math.floor(Math.random() * 5000),
      processing_time_ms: Math.floor(Math.random() * 50),
      timed_access_metadata: {
        request_timestamp: new Date().toISOString(),
        processing_timestamp: new Date().toISOString(),
        timezone_offset: 0,
        day_of_week: new Date().getDay(),
        hour_of_day: new Date().getHours(),
        is_business_hours: true,
        is_weekend: false,
        week_of_year: 1,
        month_of_year: 1,
        quarter_of_year: 1,
      },
      previous_hash: "hash",
      current_hash: "hash",
      sequence_number: this.auditEntries.length + 1,
      metadata: { demo: "true" },
    };

    // Keep only last 1000 entries
    this.auditEntries.unshift(entry);
    if (this.auditEntries.length > 1000) {
      this.auditEntries.pop();
    }
  }

  // --- Methods ---

  getAgents(page: number, pageSize: number): AgentListResponse {
    const start = (page - 1) * pageSize;
    const end = start + pageSize;
    return {
      agents: this.agents.slice(start, end),
      total_count: this.agents.length,
      page,
      page_size: pageSize,
      has_more: end < this.agents.length,
    };
  }

  getAgent(id: string): AgentDTO | undefined {
    return this.agents.find(a => a.agent_id === id);
  }

  createAgent(data: CreateAgentRequest): AgentDTO {
    const newAgent: AgentDTO = {
      agent_id: uuidv4(),
      tenant_id: this.tenantId,
      name: data.name,
      status: "pending",
      certificate_fingerprint: "sha256:mock_generated_" + uuidv4().substring(0, 8),
      certificate_subject: `CN=${data.name}`,
      certificate_expiry: new Date(Date.now() + 86400000 * 90).toISOString(),
      policy_ids: [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_seen_at: null,
      metadata: data.metadata || {},
      version: 1,
    };
    this.agents.push(newAgent);
    return newAgent;
  }

  updateAgent(id: string, data: UpdateAgentRequest): AgentDTO {
    const agent = this.agents.find(a => a.agent_id === id);
    if (!agent) throw new Error("Agent not found");

    if (data.name) agent.name = data.name;
    if (data.status === "active" || data.status === "suspended") {
        agent.status = data.status;
    } else if (data.status === "pending_activation") {
        agent.status = "pending";
    }
    // minimal update logic for demo
    agent.updated_at = new Date().toISOString();
    return agent;
  }

  getPolicies(page: number, pageSize: number): PolicyListResponse {
    const start = (page - 1) * pageSize;
    const end = start + pageSize;
    return {
      policies: this.policies.slice(start, end),
      total_count: this.policies.length,
      page,
      page_size: pageSize,
      has_more: end < this.policies.length,
    };
  }

  getPolicy(id: string): PolicyDTO | undefined {
    return this.policies.find(p => p.policy_id === id);
  }

  createPolicy(data: CreatePolicyRequest): PolicyDTO {
    const newPolicy: PolicyDTO = {
      policy_id: uuidv4(),
      tenant_id: this.tenantId,
      name: data.name,
      description: data.description,
      rules: [],
      time_restrictions: null,
      rate_limits: null,
      priority: data.priority || 0,
      status: "active",
      allowed_domains: data.allowed_domains || [],
      blocked_domains: data.blocked_domains || [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      created_by: this.userId,
      version: 1,
      metadata: {},
    };
    this.policies.push(newPolicy);
    return newPolicy;
  }

  updatePolicy(id: string, data: UpdatePolicyRequest): PolicyDTO {
    const policy = this.policies.find(p => p.policy_id === id);
    if (!policy) throw new Error("Policy not found");

    if (data.name) policy.name = data.name;
    if (data.description) policy.description = data.description;
    if (data.allowed_domains) policy.allowed_domains = data.allowed_domains;

    policy.updated_at = new Date().toISOString();
    return policy;
  }

  deletePolicy(id: string): void {
    this.policies = this.policies.filter(p => p.policy_id !== id);
  }

  getAuditLogs(params: AuditQueryRequest): AuditListResponse {
    let filtered = [...this.auditEntries];
    if (params.agent_id) filtered = filtered.filter(e => e.agent_id === params.agent_id);
    if (params.decision) filtered = filtered.filter(e => e.decision === params.decision);

    // Sort by timestamp desc
    filtered.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    const page = params.page || 1;
    const pageSize = params.page_size || 50;
    const start = (page - 1) * pageSize;
    const end = start + pageSize;

    return {
      entries: filtered.slice(start, end),
      total_count: filtered.length,
      page,
      page_size: pageSize,
      has_more: end < filtered.length,
    };
  }

  getTemporalAnalytics(startTime: string, endTime: string): TemporalPatternDTO {
    // Generate fake analytics based on audit logs in that range
     return {
        tenant_id: this.tenantId,
        start_time: startTime,
        end_time: endTime,
        hourly_distribution: { 9: 10, 10: 20, 11: 15 },
        daily_distribution: { "2025-01-01": 100 },
        peak_hours: [10],
        off_hours_activity_percentage: 5,
        weekend_activity_percentage: 2,
        top_domains: [{ domain: "google.com", count: 50 }, { domain: "github.com", count: 30 }],
        anomalies: [],
        compliance_score: 98,
     };
  }

  getMetrics(): MetricsSummaryResponse {
      return {
          timestamp: new Date().toISOString(),
          agents: {
              total: this.agents.length,
              active: this.agents.filter(a => a.status === 'active').length,
              suspended: this.agents.filter(a => a.status === 'suspended').length,
              pending: this.agents.filter(a => a.status === 'pending').length,
          },
          policies: {
              total: this.policies.length,
              active: this.policies.filter(p => p.status === 'active').length,
          },
          recent_activity: null
      };
  }
}

// Singleton instance
const store = new MockDataStore();

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Mock API Export
export const mockApi = {
  auth: {
    login: async () => {
        await delay(500);
        return {
            data: {
                access_token: "mock_token",
                token_type: "bearer",
                tenant_id: "demo-tenant",
                user_id: "demo-user",
                expires_in: 3600
            }
        };
    },
    logout: async () => { await delay(200); return { data: null }; },
    session: async () => {
        await delay(200);
        return { data: { authenticated: true, tenant_id: "demo-tenant", user_id: "demo-user" } };
    },
  },
  health: {
    check: async () => ({ data: { status: "ok", timestamp: new Date().toISOString(), service: "chronoguard-mock", version: "1.0.0-demo" } }),
    ready: async () => ({ data: { status: "ok", timestamp: new Date().toISOString(), service: "chronoguard-mock", version: "1.0.0-demo" } }),
    metrics: async () => {
        await delay(300);
        return { data: store.getMetrics() };
    },
  },
  agents: {
    list: async (page = 1, pageSize = 50) => {
        await delay(300);
        return { data: store.getAgents(page, pageSize) };
    },
    get: async (id: string) => {
        await delay(200);
        const agent = store.getAgent(id);
        if (!agent) throw { response: { status: 404 } };
        return { data: agent };
    },
    create: async (data: CreateAgentRequest) => {
        await delay(500);
        return { data: store.createAgent(data) };
    },
    update: async (id: string, data: UpdateAgentRequest) => {
        await delay(400);
        return { data: store.updateAgent(id, data) };
    },
  },
  policies: {
    list: async (page = 1, pageSize = 50) => {
        await delay(300);
        return { data: store.getPolicies(page, pageSize) };
    },
    get: async (id: string) => {
        await delay(200);
        const policy = store.getPolicy(id);
        if (!policy) throw { response: { status: 404 } };
        return { data: policy };
    },
    create: async (data: CreatePolicyRequest) => {
        await delay(500);
        return { data: store.createPolicy(data) };
    },
    update: async (id: string, data: UpdatePolicyRequest) => {
        await delay(400);
        return { data: store.updatePolicy(id, data) };
    },
    delete: async (id: string) => {
        await delay(300);
        store.deletePolicy(id);
        return { data: null };
    },
  },
  audit: {
    query: async (params: AuditQueryRequest) => {
        await delay(400);
        return { data: store.getAuditLogs(params) };
    },
    analytics: async (startTime: string, endTime: string) => {
        await delay(500);
        return { data: store.getTemporalAnalytics(startTime, endTime) };
    },
    export: async () => {
        await delay(1000);
        return { data: new Blob(["entry_id,timestamp,decision\ne1,2025-01-01,allow"], { type: "text/csv" }) };
    }
  }
};
