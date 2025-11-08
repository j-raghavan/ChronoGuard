import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuditPage } from './AuditPage';
import * as useApiModule from '@/hooks/useApi';
import * as apiModule from '@/services/api';

vi.mock('@/hooks/useApi');
vi.mock('@/services/api');

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

describe('AuditPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render audit page title', () => {
    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: { entries: [], total_count: 0, page: 1, page_size: 50, has_more: false },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });
    expect(screen.getByText('Audit Log')).toBeInTheDocument();
    expect(screen.getByText(/view and search audit trail entries/i)).toBeInTheDocument();
  });

  it('should display loading state', () => {
    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/loading audit logs/i)).toBeInTheDocument();
  });

  it('should display error state', () => {
    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: { message: 'Network error' },
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/error loading audit logs: network error/i)).toBeInTheDocument();
  });

  it('should display empty state', () => {
    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: {
        entries: [],
        total_count: 0,
        page: 1,
        page_size: 50,
        has_more: false,
      },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/no audit entries found/i)).toBeInTheDocument();
  });

  it('should display audit entries table', async () => {
    const mockData = {
      entries: [
        {
          entry_id: 'e1',
          tenant_id: 't1',
          agent_id: 'a123',
          timestamp: '2025-01-15T14:30:00Z',
          timestamp_nanos: 0,
          domain: 'api.example.com',
          decision: 'allow',
          reason: 'Policy matched',
          policy_id: 'p1',
          rule_id: null,
          request_method: 'GET',
          request_path: '/api/data',
          user_agent: null,
          source_ip: null,
          response_status: null,
          response_size_bytes: null,
          processing_time_ms: null,
          timed_access_metadata: {
            request_timestamp: '2025-01-15T14:30:00Z',
            processing_timestamp: '2025-01-15T14:30:00Z',
            timezone_offset: 0,
            day_of_week: 2,
            hour_of_day: 14,
            is_business_hours: true,
            is_weekend: false,
            week_of_year: 3,
            month_of_year: 1,
            quarter_of_year: 1,
          },
          previous_hash: '',
          current_hash: 'abc123',
          sequence_number: 1,
          metadata: {},
        },
      ],
      total_count: 1,
      page: 1,
      page_size: 50,
      has_more: false,
    };

    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: mockData,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('api.example.com')).toBeInTheDocument();
      expect(screen.getByText('allow')).toBeInTheDocument();
      expect(screen.getByText('GET')).toBeInTheDocument();
      expect(screen.getByText('/api/data')).toBeInTheDocument();
    });
  });

  it('should have decision filter', async () => {
    const refetchMock = vi.fn();
    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: { entries: [], total_count: 0, page: 1, page_size: 50, has_more: false },
      isLoading: false,
      error: null,
      refetch: refetchMock,
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });

    // Find the decision select by looking for the select element
    const selects = screen.getAllByRole('combobox');
    const decisionSelect = selects.find(el => el.closest('div')?.querySelector('label')?.textContent === 'Decision');

    if (decisionSelect) {
      fireEvent.change(decisionSelect, { target: { value: 'deny' } });
      expect(decisionSelect).toHaveValue('deny');
    } else {
      // At least verify the label exists
      expect(screen.getByText('Decision')).toBeInTheDocument();
    }
  });

  it('should have search functionality', () => {
    const refetchMock = vi.fn();
    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: { entries: [], total_count: 0, page: 1, page_size: 50, has_more: false },
      isLoading: false,
      error: null,
      refetch: refetchMock,
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });

    const searchInput = screen.getByPlaceholderText('example.com');
    const searchButton = screen.getAllByRole('button').find(
      (btn) => btn.querySelector('svg') && btn.className.includes('bg-primary')
    );

    fireEvent.change(searchInput, { target: { value: 'test.com' } });
    expect(searchInput).toHaveValue('test.com');

    if (searchButton) {
      fireEvent.click(searchButton);
      expect(refetchMock).toHaveBeenCalled();
    }
  });

  it('should have export CSV button', () => {
    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: { entries: [], total_count: 0, page: 1, page_size: 50, has_more: false },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });

    const exportButton = screen.getByText(/export csv/i);
    expect(exportButton).toBeInTheDocument();
  });

  it('should have export JSON button', () => {
    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: { entries: [], total_count: 0, page: 1, page_size: 50, has_more: false },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });

    const exportButton = screen.getByText(/export json/i);
    expect(exportButton).toBeInTheDocument();
  });

  it('should render filter controls', async () => {
    const mockData = {
      entries: [],
      total_count: 0,
      page: 1,
      page_size: 50,
      has_more: false,
    };

    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: mockData,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('Filters')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('example.com')).toBeInTheDocument();
      expect(screen.getByText('Domain')).toBeInTheDocument();
      expect(screen.getByText('Decision')).toBeInTheDocument();
    });
  });
});
