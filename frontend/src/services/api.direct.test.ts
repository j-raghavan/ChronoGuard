/**
 * Direct tests for api.ts to ensure code execution and coverage
 * These tests import the actual api module to test interceptors and methods
 */
import { describe, it, expect, vi, beforeAll } from "vitest";
import axios from "axios";
import MockAdapter from "axios-mock-adapter";

describe("API Direct Execution Tests", () => {
  let mock: MockAdapter;

  beforeAll(() => {
    mock = new MockAdapter(axios);
  });

  beforeAll(async () => {
    // Import api module to execute module-level code
    await import("./api");
  });

  it("should have apiClient created", async () => {
    const { apiClient } = await import("./api");
    expect(apiClient).toBeDefined();
    expect(typeof apiClient.get).toBe("function");
    expect(typeof apiClient.post).toBe("function");
    expect(typeof apiClient.put).toBe("function");
    expect(typeof apiClient.delete).toBe("function");
  });

  it("should have healthApi methods", async () => {
    const { healthApi } = await import("./api");
    expect(healthApi.check).toBeDefined();
    expect(healthApi.ready).toBeDefined();
    expect(healthApi.metrics).toBeDefined();
  });

  it("should have agentApi methods", async () => {
    const { agentApi } = await import("./api");
    expect(agentApi.list).toBeDefined();
    expect(agentApi.get).toBeDefined();
    expect(agentApi.create).toBeDefined();
    expect(agentApi.update).toBeDefined();
  });

  it("should have policyApi methods", async () => {
    const { policyApi } = await import("./api");
    expect(policyApi.list).toBeDefined();
    expect(policyApi.get).toBeDefined();
    expect(policyApi.create).toBeDefined();
    expect(policyApi.update).toBeDefined();
    expect(policyApi.delete).toBeDefined();
  });

  it("should have auditApi methods", async () => {
    const { auditApi } = await import("./api");
    expect(auditApi.query).toBeDefined();
    expect(auditApi.analytics).toBeDefined();
    expect(auditApi.export).toBeDefined();
  });

  it("should call healthApi.check", async () => {
    mock.onGet("/api/v1/health/").reply(200, { status: "healthy" });

    const { healthApi } = await import("./api");
    const result = await healthApi.check();

    expect(result.data.status).toBe("healthy");
  });

  it("should call healthApi.ready", async () => {
    mock.onGet("/api/v1/health/ready").reply(200, { status: "ready" });

    const { healthApi } = await import("./api");
    const result = await healthApi.ready();

    expect(result.data.status).toBe("ready");
  });

  it("should call healthApi.metrics", async () => {
    mock.onGet("/api/v1/health/metrics").reply(200, { agents: { total: 5 } });

    const { healthApi } = await import("./api");
    const result = await healthApi.metrics();

    expect(result.data.agents.total).toBe(5);
  });

  it("should call agentApi.list with pagination", async () => {
    mock
      .onGet("/api/v1/agents/")
      .reply(200, { agents: [], page: 2, page_size: 100 });

    const { agentApi } = await import("./api");
    const result = await agentApi.list(2, 100);

    expect(result.data.page).toBe(2);
    expect(result.data.page_size).toBe(100);
  });

  it("should call agentApi.get", async () => {
    mock
      .onGet("/api/v1/agents/123")
      .reply(200, { agent_id: "123", name: "test" });

    const { agentApi } = await import("./api");
    const result = await agentApi.get("123");

    expect(result.data.agent_id).toBe("123");
  });

  it("should call agentApi.create", async () => {
    mock.onPost("/api/v1/agents/").reply(201, { agent_id: "456", name: "new" });

    const { agentApi } = await import("./api");
    const result = await agentApi.create({
      name: "new",
      certificate_pem: "cert",
    });

    expect(result.data.agent_id).toBe("456");
  });

  it("should call agentApi.update", async () => {
    mock
      .onPut("/api/v1/agents/123")
      .reply(200, { agent_id: "123", name: "updated" });

    const { agentApi } = await import("./api");
    const result = await agentApi.update("123", { name: "updated" });

    expect(result.data.name).toBe("updated");
  });

  it("should call policyApi.list with pagination", async () => {
    mock.onGet("/api/v1/policies/").reply(200, { policies: [], page: 1 });

    const { policyApi } = await import("./api");
    const result = await policyApi.list(1, 50);

    expect(result.data.page).toBe(1);
  });

  it("should call policyApi.get", async () => {
    mock.onGet("/api/v1/policies/789").reply(200, { policy_id: "789" });

    const { policyApi } = await import("./api");
    const result = await policyApi.get("789");

    expect(result.data.policy_id).toBe("789");
  });

  it("should call policyApi.create", async () => {
    mock
      .onPost("/api/v1/policies/")
      .reply(201, { policy_id: "999", name: "new" });

    const { policyApi } = await import("./api");
    const result = await policyApi.create({ name: "new", description: "Test" });

    expect(result.data.policy_id).toBe("999");
  });

  it("should call policyApi.update", async () => {
    mock
      .onPut("/api/v1/policies/789")
      .reply(200, { policy_id: "789", name: "updated" });

    const { policyApi } = await import("./api");
    const result = await policyApi.update("789", { name: "updated" });

    expect(result.data.name).toBe("updated");
  });

  it("should call policyApi.delete", async () => {
    mock.onDelete("/api/v1/policies/789").reply(204);

    const { policyApi } = await import("./api");
    const result = await policyApi.delete("789");

    expect(result.status).toBe(204);
  });

  it("should call auditApi.query", async () => {
    mock.onPost("/api/v1/audit/query").reply(200, { entries: [], page: 1 });

    const { auditApi } = await import("./api");
    const result = await auditApi.query({ page: 1, page_size: 50 });

    expect(result.data.page).toBe(1);
  });

  it("should call auditApi.analytics", async () => {
    mock
      .onGet("/api/v1/audit/analytics")
      .reply(200, { compliance_score: 92.5 });

    const { auditApi } = await import("./api");
    const result = await auditApi.analytics(
      "2025-01-01T00:00:00Z",
      "2025-01-31T23:59:59Z",
    );

    expect(result.data.compliance_score).toBe(92.5);
  });

  it("should call auditApi.export with CSV format", async () => {
    mock
      .onPost("/api/v1/audit/export")
      .reply(200, "data", { "content-type": "text/csv" });

    const { auditApi } = await import("./api");
    const result = await auditApi.export(
      "csv",
      "2025-01-01T00:00:00Z",
      "2025-01-31T23:59:59Z",
    );

    expect(result.status).toBe(200);
  });

  it("should call auditApi.export with JSON format", async () => {
    mock
      .onPost("/api/v1/audit/export")
      .reply(200, "{}", { "content-type": "application/json" });

    const { auditApi } = await import("./api");
    const result = await auditApi.export(
      "json",
      "2025-01-01T00:00:00Z",
      "2025-01-31T23:59:59Z",
    );

    expect(result.status).toBe(200);
  });

  it("should add tenantId header via interceptor", async () => {
    localStorage.setItem("tenantId", "test-tenant-123");

    mock.onGet("/api/v1/health/").reply((config) => {
      // Interceptor should add this header
      expect(config.headers?.["X-Tenant-ID"]).toBe("test-tenant-123");
      return [200, { status: "ok" }];
    });

    const { healthApi } = await import("./api");
    await healthApi.check();
  });

  it("should add userId header via interceptor", async () => {
    localStorage.setItem("userId", "test-user-456");

    mock.onGet("/api/v1/health/").reply((config) => {
      expect(config.headers?.["X-User-ID"]).toBe("test-user-456");
      return [200, { status: "ok" }];
    });

    const { healthApi } = await import("./api");
    await healthApi.check();
  });

  it("should handle 401 error in response interceptor", async () => {
    const consoleErrorSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});

    mock.onGet("/api/v1/agents/").reply(401, { detail: "Unauthorized" });

    const { agentApi } = await import("./api");

    try {
      await agentApi.list();
    } catch (error: any) {
      expect(error.response.status).toBe(401);
    }

    consoleErrorSpy.mockRestore();
  });
});
