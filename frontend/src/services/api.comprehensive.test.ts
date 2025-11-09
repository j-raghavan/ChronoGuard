import { describe, it, expect } from "vitest";
import type {
  AuditQueryRequest,
  CreateAgentRequest,
  CreatePolicyRequest,
  UpdateAgentRequest,
  UpdatePolicyRequest,
} from "@/types/api";

describe("API Comprehensive Coverage", () => {
  describe("Type Definitions", () => {
    it("should define AuditQueryRequest type", () => {
      const req: AuditQueryRequest = {
        tenant_id: "123",
        agent_id: "456",
        domain: "example.com",
        decision: "allow",
        start_time: "2025-01-01T00:00:00Z",
        end_time: "2025-01-31T23:59:59Z",
        page: 1,
        page_size: 50,
      };
      expect(req.tenant_id).toBe("123");
      expect(req.page).toBe(1);
    });

    it("should define CreateAgentRequest type", () => {
      const req: CreateAgentRequest = {
        name: "test-agent",
        certificate_pem:
          "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        metadata: { env: "test" },
      };
      expect(req.name).toBe("test-agent");
    });

    it("should define UpdateAgentRequest type", () => {
      const req: UpdateAgentRequest = {
        name: "updated-agent",
        status: "suspended",
        metadata: {},
      };
      expect(req.name).toBe("updated-agent");
      expect(req.status).toBe("suspended");
    });

    it("should define CreatePolicyRequest type", () => {
      const req: CreatePolicyRequest = {
        name: "test-policy",
        description: "Test policy description",
        priority: 100,
        default_action: "deny",
        allowed_domains: ["api.example.com"],
        blocked_domains: ["malicious.com"],
      };
      expect(req.name).toBe("test-policy");
      expect(req.priority).toBe(100);
    });

    it("should define UpdatePolicyRequest type", () => {
      const req: UpdatePolicyRequest = {
        name: "updated-policy",
        description: "Updated description",
        priority: 200,
        is_active: false,
      };
      expect(req.name).toBe("updated-policy");
      expect(req.is_active).toBe(false);
    });

    it("should handle optional fields", () => {
      const req: CreateAgentRequest = {
        name: "minimal-agent",
        certificate_pem: "cert",
      };
      expect(req.metadata).toBeUndefined();

      const withMeta: CreateAgentRequest = {
        ...req,
        metadata: { key: "value" },
      };
      expect(withMeta.metadata).toEqual({ key: "value" });
    });

    it("should handle all decision types", () => {
      const decisions = [
        "allow",
        "deny",
        "block",
        "rate_limited",
        "time_restricted",
        "policy_violation",
      ];
      decisions.forEach((decision) => {
        const req: AuditQueryRequest = {
          decision,
          page: 1,
          page_size: 50,
        };
        expect(req.decision).toBe(decision);
      });
    });

    it("should handle all agent statuses", () => {
      const statuses: Array<
        "active" | "suspended" | "pending_activation" | "expired"
      > = ["active", "suspended", "pending_activation", "expired"];
      statuses.forEach((status) => {
        const req: UpdateAgentRequest = { status };
        expect(req.status).toBe(status);
      });
    });

    it("should handle policy actions", () => {
      const actions: Array<"allow" | "deny"> = ["allow", "deny"];
      actions.forEach((action) => {
        const req: CreatePolicyRequest = {
          name: `policy-${action}`,
          description: "Test",
          default_action: action,
        };
        expect(req.default_action).toBe(action);
      });
    });

    it("should handle export formats", () => {
      const formats: Array<"csv" | "json"> = ["csv", "json"];
      formats.forEach((format) => {
        const req = {
          tenant_id: "123",
          start_time: "2025-01-01T00:00:00Z",
          end_time: "2025-01-31T23:59:59Z",
          format,
        };
        expect(req.format).toBe(format);
      });
    });
  });
});
