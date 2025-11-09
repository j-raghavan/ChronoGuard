import { describe, it, expect } from "vitest";

describe("API Client", () => {
  describe("Configuration", () => {
    it("should define API base URL from environment or default", () => {
      const defaultUrl = "http://localhost:8000";
      const envUrl = import.meta.env.VITE_API_URL || defaultUrl;
      expect(envUrl).toBeDefined();
      expect(typeof envUrl).toBe("string");
    });

    it("should have tenantId in localStorage", () => {
      const tenantId = localStorage.getItem("tenantId");
      expect(tenantId).toBe("550e8400-e29b-41d4-a716-446655440000");
    });
  });
});
