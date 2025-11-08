import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuditPage } from './AuditPage';
import * as useApiModule from '@/hooks/useApi';

vi.mock('@/hooks/useApi');

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

describe('AuditPage Display Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should display deny decision with red badge', async () => {
    const mockData = {
      entries: [
        {
          entry_id: 'e1',
          tenant_id: 't1',
          agent_id: 'a123',
          timestamp: '2025-01-15T14:30:00Z',
          timestamp_nanos: 0,
          domain: 'blocked.example.com',
          decision: 'deny',
          reason: 'Policy violation',
          policy_id: 'p1',
          rule_id: null,
          request_method: 'POST',
          request_path: '/api/admin',
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
      expect(screen.getByText('deny')).toBeInTheDocument();
      expect(screen.getByText('blocked.example.com')).toBeInTheDocument();
      expect(screen.getByText('POST')).toBeInTheDocument();
    });
  });

  it('should display multiple audit entries', async () => {
    const mockData = {
      entries: [
        {
          entry_id: 'e1',
          tenant_id: 't1',
          agent_id: 'a111',
          timestamp: '2025-01-15T14:30:00Z',
          timestamp_nanos: 0,
          domain: 'api1.example.com',
          decision: 'allow',
          reason: 'Allowed',
          policy_id: null,
          rule_id: null,
          request_method: 'GET',
          request_path: '/api/v1/data',
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
          current_hash: 'hash1',
          sequence_number: 1,
          metadata: {},
        },
        {
          entry_id: 'e2',
          tenant_id: 't1',
          agent_id: 'a222',
          timestamp: '2025-01-15T15:00:00Z',
          timestamp_nanos: 0,
          domain: 'api2.example.com',
          decision: 'deny',
          reason: 'Blocked',
          policy_id: null,
          rule_id: null,
          request_method: 'POST',
          request_path: '/api/v1/admin',
          user_agent: null,
          source_ip: null,
          response_status: null,
          response_size_bytes: null,
          processing_time_ms: null,
          timed_access_metadata: {
            request_timestamp: '2025-01-15T15:00:00Z',
            processing_timestamp: '2025-01-15T15:00:00Z',
            timezone_offset: 0,
            day_of_week: 2,
            hour_of_day: 15,
            is_business_hours: true,
            is_weekend: false,
            week_of_year: 3,
            month_of_year: 1,
            quarter_of_year: 1,
          },
          previous_hash: 'hash1',
          current_hash: 'hash2',
          sequence_number: 2,
          metadata: {},
        },
      ],
      total_count: 2,
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
      expect(screen.getByText('api1.example.com')).toBeInTheDocument();
      expect(screen.getByText('api2.example.com')).toBeInTheDocument();
      expect(screen.getByText(/showing 2 of 2 entries/i)).toBeInTheDocument();
    });
  });

  it('should truncate long paths', async () => {
    const longPath = '/api/v1/very/long/path/that/should/be/truncated/in/the/display';
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
          reason: 'OK',
          policy_id: null,
          rule_id: null,
          request_method: 'GET',
          request_path: longPath,
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
          current_hash: 'abc',
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
      expect(screen.getByText(longPath)).toBeInTheDocument();
    });
  });

  it('should show filter UI elements', () => {
    vi.mocked(useApiModule.useAuditQuery).mockReturnValue({
      data: { entries: [], total_count: 0, page: 1, page_size: 50, has_more: false },
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as any);

    render(<AuditPage />, { wrapper: createWrapper() });

    expect(screen.getByText('Filters')).toBeInTheDocument();
    expect(screen.getByText('Domain')).toBeInTheDocument();
    expect(screen.getByText('Decision')).toBeInTheDocument();
    expect(screen.getByText('Start Date')).toBeInTheDocument();
    expect(screen.getByText('End Date')).toBeInTheDocument();
  });
});
