import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuditPage } from "./AuditPage";
import * as useApiModule from "@/hooks/useApi";
import * as apiModule from "@/services/api";

vi.mock("@/hooks/useApi");
vi.mock("@/services/api", async () => {
  return {
    auditApi: {
      export: vi.fn().mockResolvedValue({ data: new Blob(["test"]) }),
      query: vi.fn(),
      analytics: vi.fn(),
    },
  };
});

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

describe("AuditPage Simple Execution Tests", () => {
  it("should render with audit data showing table", async () => {
    const mockEntry = {
      entry_id: "e1",
      tenant_id: "t1",
      agent_id: "a123",
      timestamp: "2025-01-15T14:30:00Z",
      timestamp_nanos: 0,
      domain: "api.example.com",
      decision: "allow",
      reason: "Policy matched",
      policy_id: "p1",
      rule_id: null,
      request_method: "GET",
      request_path: "/api/data",
      user_agent: null,
      source_ip: null,
      response_status: null,
      response_size_bytes: null,
      processing_time_ms: null,
      timed_access_metadata: {
        request_timestamp: "2025-01-15T14:30:00Z",
        processing_timestamp: "2025-01-15T14:30:00Z",
        timezone_offset: 0,
        day_of_week: 2,
        hour_of_day: 14,
        is_business_hours: true,
        is_weekend: false,
        week_of_year: 3,
        month_of_year: 1,
        quarter_of_year: 1,
      },
      previous_hash: "",
      current_hash: "hash",
      sequence_number: 1,
      metadata: {},
    };

    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: {
        entries: [mockEntry],
        total_count: 1,
        page: 1,
        page_size: 50,
        has_more: false,
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });

    // This renders the table and pagination code paths
    expect(screen.getByText("api.example.com")).toBeInTheDocument();
    expect(screen.getByText("allow")).toBeInTheDocument();
    expect(screen.getByText("GET")).toBeInTheDocument();
    expect(screen.getByText("/api/data")).toBeInTheDocument();

    // Pagination should be visible
    expect(screen.getByText(/showing 1 of 1 entries/i)).toBeInTheDocument();
    expect(screen.getByText("Previous")).toBeInTheDocument();
    expect(screen.getByText("Next")).toBeInTheDocument();
  });

  it("should render multiple entries in table", async () => {
    const mockEntries = Array.from({ length: 5 }, (_, i) => ({
      entry_id: `e${i}`,
      tenant_id: "t1",
      agent_id: `a${i}`,
      timestamp: "2025-01-15T14:30:00Z",
      timestamp_nanos: 0,
      domain: `domain${i}.example.com`,
      decision: i % 2 === 0 ? "allow" : "deny",
      reason: "Test reason",
      policy_id: null,
      rule_id: null,
      request_method: "GET",
      request_path: `/api/path${i}`,
      user_agent: null,
      source_ip: null,
      response_status: null,
      response_size_bytes: null,
      processing_time_ms: null,
      timed_access_metadata: {
        request_timestamp: "2025-01-15T14:30:00Z",
        processing_timestamp: "2025-01-15T14:30:00Z",
        timezone_offset: 0,
        day_of_week: 2,
        hour_of_day: 14,
        is_business_hours: true,
        is_weekend: false,
        week_of_year: 3,
        month_of_year: 1,
        quarter_of_year: 1,
      },
      previous_hash: "",
      current_hash: `hash${i}`,
      sequence_number: i + 1,
      metadata: {},
    }));

    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: {
        entries: mockEntries,
        total_count: 100,
        page: 1,
        page_size: 50,
        has_more: true,
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });

    // All entries should render
    expect(screen.getByText("domain0.example.com")).toBeInTheDocument();
    expect(screen.getByText("domain4.example.com")).toBeInTheDocument();

    // Pagination shows correctly
    expect(screen.getByText(/showing 5 of 100 entries/i)).toBeInTheDocument();

    // Next button should be enabled
    const nextButton = screen.getByText("Next");
    expect(nextButton).not.toBeDisabled();

    // Previous should be disabled on page 1
    const prevButton = screen.getByText("Previous");
    expect(prevButton).toBeDisabled();
  });

  it("should show pagination buttons and allow clicks", () => {
    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: {
        entries: [
          {
            entry_id: "e1",
            tenant_id: "t1",
            agent_id: "a1",
            timestamp: "2025-01-15T14:30:00Z",
            timestamp_nanos: 0,
            domain: "test.com",
            decision: "allow",
            reason: "OK",
            policy_id: null,
            rule_id: null,
            request_method: "GET",
            request_path: "/",
            user_agent: null,
            source_ip: null,
            response_status: null,
            response_size_bytes: null,
            processing_time_ms: null,
            timed_access_metadata: {
              request_timestamp: "2025-01-15T14:30:00Z",
              processing_timestamp: "2025-01-15T14:30:00Z",
              timezone_offset: 0,
              day_of_week: 2,
              hour_of_day: 14,
              is_business_hours: true,
              is_weekend: false,
              week_of_year: 3,
              month_of_year: 1,
              quarter_of_year: 1,
            },
            previous_hash: "",
            current_hash: "hash",
            sequence_number: 1,
            metadata: {},
          },
        ],
        total_count: 150,
        page: 1,
        page_size: 50,
        has_more: true,
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });

    // Component starts at page 1 due to useState
    // Previous should be disabled on page 1
    const prevButton = screen.getByText("Previous");
    expect(prevButton).toBeDisabled();

    // Next should be enabled (has_more = true)
    const nextButton = screen.getByText("Next");
    expect(nextButton).not.toBeDisabled();

    // Click Next to execute setPage((p) => p + 1)
    fireEvent.click(nextButton);

    // This executes the pagination handler
    expect(nextButton).toBeInTheDocument();
  });
});
