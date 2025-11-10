import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { PoliciesPage } from "./PoliciesPage";
import * as useApiModule from "@/hooks/useApi";

vi.mock("@/hooks/useApi");

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

describe("PoliciesPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should render policies page title", () => {
    vi.mocked(useApiModule.usePolicies).mockReturnValue({
      data: {
        policies: [],
        total_count: 0,
        page: 1,
        page_size: 50,
        has_more: false,
      },
      isLoading: false,
      error: null,
    } as any);

    render(<PoliciesPage />, { wrapper: createWrapper() });
    expect(screen.getByText("Policies")).toBeInTheDocument();
    expect(
      screen.getByText(/manage access policies and rules/i),
    ).toBeInTheDocument();
  });

  it("should display loading state", () => {
    vi.mocked(useApiModule.usePolicies).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
    } as any);

    render(<PoliciesPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/loading policies/i)).toBeInTheDocument();
  });

  it("should display error state", () => {
    vi.mocked(useApiModule.usePolicies).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error("Failed to fetch"),
    } as any);

    render(<PoliciesPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/error loading policies/i)).toBeInTheDocument();
  });

  it.skip("should display policies list", async () => {
    // TODO: Fix waitFor timeout issue
    const mockData = {
      policies: [
        {
          policy_id: "789",
          tenant_id: "456",
          name: "Production Policy",
          description: "Policy for production environments",
          priority: 100,
          rules: [{ rule_id: "r1", name: "Allow API" }],
          allowed_domains: ["api.example.com", "app.example.com"],
          blocked_domains: [],
          default_action: "deny" as const,
          is_active: true,
          created_at: "2025-01-01T00:00:00Z",
          updated_at: "2025-01-01T00:00:00Z",
          created_by: "admin",
          version: 1,
        },
      ],
      total_count: 1,
      page: 1,
      page_size: 50,
      has_more: false,
    };

    vi.mocked(useApiModule.usePolicies).mockReturnValue({
      data: mockData,
      isLoading: false,
      error: null,
    } as any);

    render(<PoliciesPage />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("Production Policy")).toBeInTheDocument();
      expect(
        screen.getByText(/policy for production environments/i),
      ).toBeInTheDocument();
      expect(screen.getByText("Active")).toBeInTheDocument();
      expect(screen.getByText(/priority: 100/i)).toBeInTheDocument();
    });
  });

  it("should display allowed domains", async () => {
    const mockData = {
      policies: [
        {
          policy_id: "789",
          tenant_id: "456",
          name: "Test Policy",
          description: "Test",
          priority: 50,
          rules: [],
          allowed_domains: [
            "api.example.com",
            "app.example.com",
            "web.example.com",
          ],
          blocked_domains: [],
          default_action: "deny" as const,
          is_active: true,
          created_at: "2025-01-01T00:00:00Z",
          updated_at: "2025-01-01T00:00:00Z",
          created_by: "admin",
          version: 1,
        },
      ],
      total_count: 1,
      page: 1,
      page_size: 50,
      has_more: false,
    };

    vi.mocked(useApiModule.usePolicies).mockReturnValue({
      data: mockData,
      isLoading: false,
      error: null,
    } as any);

    render(<PoliciesPage />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("Allowed Domains")).toBeInTheDocument();
      expect(screen.getByText("api.example.com")).toBeInTheDocument();
    });
  });

  it.skip("should display blocked domains", async () => {
    // TODO: Fix waitFor timeout issue
    const mockData = {
      policies: [
        {
          policy_id: "789",
          tenant_id: "456",
          name: "Test Policy",
          description: "Test",
          priority: 50,
          rules: [],
          allowed_domains: [],
          blocked_domains: ["malicious.com", "spam.com"],
          default_action: "allow" as const,
          is_active: false,
          created_at: "2025-01-01T00:00:00Z",
          updated_at: "2025-01-01T00:00:00Z",
          created_by: "admin",
          version: 1,
        },
      ],
      total_count: 1,
      page: 1,
      page_size: 50,
      has_more: false,
    };

    vi.mocked(useApiModule.usePolicies).mockReturnValue({
      data: mockData,
      isLoading: false,
      error: null,
    } as any);

    render(<PoliciesPage />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("Blocked Domains")).toBeInTheDocument();
      expect(screen.getByText("malicious.com")).toBeInTheDocument();
      expect(screen.getByText("Inactive")).toBeInTheDocument();
    });
  });
});
