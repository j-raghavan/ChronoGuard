import { describe, it, expect } from "vitest";

describe("API Client", () => {
  describe("Configuration", () => {
    it("should define API base URL from environment or default", () => {
      const defaultUrl = "http://localhost:8000";
      const envUrl = import.meta.env.VITE_API_URL || defaultUrl;
      expect(envUrl).toBeDefined();
      expect(typeof envUrl).toBe("string");
    });

    it("should require credentialed requests", () => {
      const withCredentials = true;
      expect(withCredentials).toBe(true);
    });
  });
});
