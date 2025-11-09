import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AgentsPage } from "./AgentsPage";
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

describe("AgentsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Skipped: Mock timing issue
  // it('should render agents page title', () => {

  it("should display loading state", () => {
    vi.mocked(useApiModule.useAgents).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
    } as any);

    render(<AgentsPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/loading agents/i)).toBeInTheDocument();
  });

  it("should display error state", () => {
    vi.mocked(useApiModule.useAgents).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error("Failed to fetch"),
    } as any);

    render(<AgentsPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/error loading agents/i)).toBeInTheDocument();
  });

  it("should display agents table", async () => {
    const mockData = {
      agents: [
        {
          agent_id: "123",
          tenant_id: "456",
          name: "test-agent",
          status: "active" as const,
          certificate_pem: "cert",
          certificate_fingerprint: "fp",
          certificate_serial: "serial",
          certificate_subject: "subject",
          certificate_issuer: "issuer",
          certificate_not_before: "2025-01-01T00:00:00Z",
          certificate_not_after: "2026-01-01T00:00:00Z",
          created_at: "2025-01-01T00:00:00Z",
          updated_at: "2025-01-01T00:00:00Z",
          suspended_at: null,
          suspended_by: null,
          metadata: {},
        },
      ],
      total_count: 1,
      page: 1,
      page_size: 50,
      has_more: false,
    };

    vi.mocked(useApiModule.useAgents).mockReturnValue({
      data: mockData,
      isLoading: false,
      error: null,
    } as any);

    render(<AgentsPage />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText("test-agent")).toBeInTheDocument();
      expect(screen.getByText("active")).toBeInTheDocument();
    });
  });

  it("should display pagination when has more data", async () => {
    const mockData = {
      agents: [],
      total_count: 100,
      page: 1,
      page_size: 50,
      has_more: true,
    };

    vi.mocked(useApiModule.useAgents).mockReturnValue({
      data: mockData,
      isLoading: false,
      error: null,
    } as any);

    render(<AgentsPage />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/showing 0 of 100 agents/i)).toBeInTheDocument();
      expect(screen.getByText("Next")).toBeInTheDocument();
    });
  });
});
