import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as hooks from "./useApi";
import * as apiModule from "@/services/api";
import React from "react";

vi.mock("@/services/api");

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return React.createElement(
      QueryClientProvider,
      { client: queryClient },
      children,
    );
  };
}

describe("useApi Comprehensive Coverage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Query Keys", () => {
    it("should have correct query keys structure", () => {
      expect(hooks.queryKeys.health).toEqual(["health"]);
      expect(hooks.queryKeys.metrics).toEqual(["metrics"]);
      expect(hooks.queryKeys.agents.all).toEqual(["agents"]);
      expect(hooks.queryKeys.agents.list(1)).toEqual(["agents", "list", 1]);
      expect(hooks.queryKeys.agents.detail("123")).toEqual([
        "agents",
        "detail",
        "123",
      ]);
      expect(hooks.queryKeys.policies.all).toEqual(["policies"]);
      expect(hooks.queryKeys.audit.all).toEqual(["audit"]);
    });
  });

  describe("useCreateAgent mutation", () => {
    it("should call create agent API", async () => {
      const mockResponse = { data: { agent_id: "123", name: "new-agent" } };
      vi.mocked(apiModule.agentApi.create).mockResolvedValue(
        mockResponse as any,
      );

      const { result } = renderHook(() => hooks.useCreateAgent(), {
        wrapper: createWrapper(),
      });

      result.current.mutate({ name: "new-agent", certificate_pem: "cert" });

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });
    });
  });

  describe("useUpdateAgent mutation", () => {
    it("should call update agent API", async () => {
      const mockResponse = { data: { agent_id: "123", name: "updated" } };
      vi.mocked(apiModule.agentApi.update).mockResolvedValue(
        mockResponse as any,
      );

      const { result } = renderHook(() => hooks.useUpdateAgent(), {
        wrapper: createWrapper(),
      });

      result.current.mutate({ agentId: "123", data: { name: "updated" } });

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });
    });
  });

  describe("useCreatePolicy mutation", () => {
    it("should call create policy API", async () => {
      const mockResponse = { data: { policy_id: "789", name: "new-policy" } };
      vi.mocked(apiModule.policyApi.create).mockResolvedValue(
        mockResponse as any,
      );

      const { result } = renderHook(() => hooks.useCreatePolicy(), {
        wrapper: createWrapper(),
      });

      result.current.mutate({ name: "new-policy", description: "Test" });

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });
    });
  });

  describe("useUpdatePolicy mutation", () => {
    it("should call update policy API", async () => {
      const mockResponse = { data: { policy_id: "789", name: "updated" } };
      vi.mocked(apiModule.policyApi.update).mockResolvedValue(
        mockResponse as any,
      );

      const { result } = renderHook(() => hooks.useUpdatePolicy(), {
        wrapper: createWrapper(),
      });

      result.current.mutate({ policyId: "789", data: { name: "updated" } });

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });
    });
  });

  describe("useDeletePolicy mutation", () => {
    it("should call delete policy API", async () => {
      vi.mocked(apiModule.policyApi.delete).mockResolvedValue({} as any);

      const { result } = renderHook(() => hooks.useDeletePolicy(), {
        wrapper: createWrapper(),
      });

      result.current.mutate("789");

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });
    });
  });

  describe("usePolicy query", () => {
    it("should fetch single policy", async () => {
      const mockPolicy = {
        policy_id: "789",
        name: "test",
        description: "Test",
        priority: 50,
        rules: [],
        allowed_domains: [],
        blocked_domains: [],
        default_action: "deny" as const,
        is_active: true,
        created_at: "2025-01-01T00:00:00Z",
        updated_at: "2025-01-01T00:00:00Z",
        created_by: "admin",
        tenant_id: "456",
        version: 1,
      };
      vi.mocked(apiModule.policyApi.get).mockResolvedValue({
        data: mockPolicy,
      } as any);

      const { result } = renderHook(() => hooks.usePolicy("789"), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
        expect(result.current.data?.policy_id).toBe("789");
      });
    });

    it("should not fetch when policyId is empty", () => {
      const { result } = renderHook(() => hooks.usePolicy(""), {
        wrapper: createWrapper(),
      });
      expect(result.current.fetchStatus).toBe("idle");
    });
  });

  describe("useAuditQuery query", () => {
    it("should fetch audit entries", async () => {
      const mockData = {
        entries: [],
        total_count: 0,
        page: 1,
        page_size: 50,
        has_more: false,
      };
      vi.mocked(apiModule.auditApi.query).mockResolvedValue({
        data: mockData,
      } as any);

      const { result } = renderHook(
        () => hooks.useAuditQuery({ page: 1, page_size: 50 }),
        { wrapper: createWrapper() },
      );

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
        expect(result.current.data?.page).toBe(1);
      });
    });
  });

  describe("Query with filters", () => {
    it("should support filtering by decision", async () => {
      const mockData = {
        entries: [],
        total_count: 0,
        page: 1,
        page_size: 50,
        has_more: false,
      };
      vi.mocked(apiModule.auditApi.query).mockResolvedValue({
        data: mockData,
      } as any);

      const { result } = renderHook(
        () =>
          hooks.useAuditQuery({ decision: "allow", page: 1, page_size: 50 }),
        { wrapper: createWrapper() },
      );

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });
    });

    it("should support filtering by domain", async () => {
      const mockData = {
        entries: [],
        total_count: 0,
        page: 1,
        page_size: 50,
        has_more: false,
      };
      vi.mocked(apiModule.auditApi.query).mockResolvedValue({
        data: mockData,
      } as any);

      const { result } = renderHook(
        () =>
          hooks.useAuditQuery({
            domain: "example.com",
            page: 1,
            page_size: 50,
          }),
        { wrapper: createWrapper() },
      );

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });
    });

    it("should support filtering by date range", async () => {
      const mockData = {
        entries: [],
        total_count: 0,
        page: 1,
        page_size: 50,
        has_more: false,
      };
      vi.mocked(apiModule.auditApi.query).mockResolvedValue({
        data: mockData,
      } as any);

      const { result } = renderHook(
        () =>
          hooks.useAuditQuery({
            start_time: "2025-01-01T00:00:00Z",
            end_time: "2025-01-31T23:59:59Z",
            page: 1,
            page_size: 50,
          }),
        { wrapper: createWrapper() },
      );

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });
    });
  });
});
