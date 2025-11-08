import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Dashboard } from './Dashboard';
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

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render dashboard title', () => {
    vi.mocked(useApiModule.useMetrics).mockReturnValue({
      data: { timestamp: new Date().toISOString(), agents: { total: 0, active: 0, suspended: 0, pending: 0 }, policies: { total: 0, active: 0 }, recent_activity: null },
      isLoading: false,
    } as any);
    vi.mocked(useApiModule.useAuditAnalytics).mockReturnValue({
      data: { tenant_id: '123', start_time: '2025-01-01T00:00:00Z', end_time: '2025-01-31T23:59:59Z', hourly_distribution: {}, daily_distribution: {}, peak_hours: [], off_hours_activity_percentage: 0, weekend_activity_percentage: 0, top_domains: [], anomalies: [], compliance_score: 0 },
      isLoading: false,
    } as any);

    render(<Dashboard />, { wrapper: createWrapper() });
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
  });

  it('should display loading state', () => {
    vi.mocked(useApiModule.useMetrics).mockReturnValue({
      data: undefined,
      isLoading: true,
    } as any);
    vi.mocked(useApiModule.useAuditAnalytics).mockReturnValue({
      data: undefined,
      isLoading: true,
    } as any);

    render(<Dashboard />, { wrapper: createWrapper() });
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it('should display metrics when loaded', async () => {
    const mockMetrics = {
      timestamp: new Date().toISOString(),
      agents: { total: 10, active: 8, suspended: 2, pending: 0 },
      policies: { total: 5, active: 4 },
      recent_activity: null,
    };

    const mockAnalytics = {
      tenant_id: '123',
      start_time: '2025-01-01T00:00:00Z',
      end_time: '2025-01-31T23:59:59Z',
      hourly_distribution: {},
      daily_distribution: {},
      peak_hours: [9],
      off_hours_activity_percentage: 15.5,
      weekend_activity_percentage: 8.2,
      top_domains: [],
      anomalies: [],
      compliance_score: 92.5,
    };

    vi.mocked(useApiModule.useMetrics).mockReturnValue({
      data: mockMetrics,
      isLoading: false,
      isSuccess: true,
    } as any);

    vi.mocked(useApiModule.useAuditAnalytics).mockReturnValue({
      data: mockAnalytics,
      isLoading: false,
      isSuccess: true,
    } as any);

    render(<Dashboard />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('Total Agents')).toBeInTheDocument();
      expect(screen.getByText('10')).toBeInTheDocument();
      expect(screen.getByText('Total Policies')).toBeInTheDocument();
      expect(screen.getByText('5')).toBeInTheDocument();
    });
  });

  it('should display compliance score', async () => {
    const mockAnalytics = {
      tenant_id: '123',
      start_time: '2025-01-01T00:00:00Z',
      end_time: '2025-01-31T23:59:59Z',
      hourly_distribution: {},
      daily_distribution: {},
      peak_hours: [14],
      off_hours_activity_percentage: 0,
      weekend_activity_percentage: 0,
      top_domains: [],
      anomalies: [],
      compliance_score: 87.3,
    };

    vi.mocked(useApiModule.useMetrics).mockReturnValue({
      data: { timestamp: new Date().toISOString(), agents: { total: 0, active: 0, suspended: 0, pending: 0 }, policies: { total: 0, active: 0 }, recent_activity: null },
      isLoading: false,
    } as any);

    vi.mocked(useApiModule.useAuditAnalytics).mockReturnValue({
      data: mockAnalytics,
      isLoading: false,
    } as any);

    render(<Dashboard />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('87.3%')).toBeInTheDocument();
      expect(screen.getByText('14')).toBeInTheDocument();
    });
  });

  it('should display anomalies when present', async () => {
    const mockAnalytics = {
      tenant_id: '123',
      start_time: '2025-01-01T00:00:00Z',
      end_time: '2025-01-31T23:59:59Z',
      hourly_distribution: {},
      daily_distribution: {},
      peak_hours: [],
      off_hours_activity_percentage: 0,
      weekend_activity_percentage: 0,
      top_domains: [],
      anomalies: [
        { type: 'activity_spike', severity: 'high', description: 'Unusual spike detected' },
      ],
      compliance_score: 75.0,
    };

    vi.mocked(useApiModule.useMetrics).mockReturnValue({
      data: { timestamp: new Date().toISOString(), agents: { total: 0, active: 0, suspended: 0, pending: 0 }, policies: { total: 0, active: 0 }, recent_activity: null },
      isLoading: false,
    } as any);

    vi.mocked(useApiModule.useAuditAnalytics).mockReturnValue({
      data: mockAnalytics,
      isLoading: false,
    } as any);

    render(<Dashboard />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('Recent Anomalies')).toBeInTheDocument();
      expect(screen.getByText('activity_spike')).toBeInTheDocument();
    });
  });

  it('should display top domains', async () => {
    const mockAnalytics = {
      tenant_id: '123',
      start_time: '2025-01-01T00:00:00Z',
      end_time: '2025-01-31T23:59:59Z',
      hourly_distribution: {},
      daily_distribution: {},
      peak_hours: [],
      off_hours_activity_percentage: 0,
      weekend_activity_percentage: 0,
      top_domains: [
        { domain: 'api.example.com', count: 523 },
        { domain: 'app.example.com', count: 412 },
      ],
      anomalies: [],
      compliance_score: 90.0,
    };

    vi.mocked(useApiModule.useMetrics).mockReturnValue({
      data: { timestamp: new Date().toISOString(), agents: { total: 0, active: 0, suspended: 0, pending: 0 }, policies: { total: 0, active: 0 }, recent_activity: null },
      isLoading: false,
    } as any);

    vi.mocked(useApiModule.useAuditAnalytics).mockReturnValue({
      data: mockAnalytics,
      isLoading: false,
    } as any);

    render(<Dashboard />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('Top Accessed Domains')).toBeInTheDocument();
      expect(screen.getByText('api.example.com')).toBeInTheDocument();
      expect(screen.getByText('523 requests')).toBeInTheDocument();
    });
  });
});
