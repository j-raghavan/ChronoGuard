import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useHealth, useMetrics, useAgents, useAgent, usePolicies, useAuditAnalytics } from './useApi';
import * as apiModule from '@/services/api';
import React from 'react';

vi.mock('@/services/api');

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return function Wrapper({ children }: { children: React.ReactNode }) {
    return React.createElement(QueryClientProvider, { client: queryClient }, children);
  };
}

describe('useApi hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('useHealth', () => {
    it('should fetch health check data', async () => {
      const mockData = { status: 'healthy', timestamp: new Date().toISOString(), service: 'chronoguard', version: '1.0.0' };
      vi.mocked(apiModule.healthApi.check).mockResolvedValue({ data: mockData } as any);

      const { result } = renderHook(() => useHealth(), { wrapper: createWrapper() });

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
      expect(result.current.data).toEqual(mockData);
    });
  });

  describe('useMetrics', () => {
    it('should fetch metrics data', async () => {
      const mockMetrics = {
        timestamp: new Date().toISOString(),
        agents: { total: 10, active: 8, suspended: 2, pending: 0 },
        policies: { total: 5, active: 4 },
        recent_activity: null,
      };
      vi.mocked(apiModule.healthApi.metrics).mockResolvedValue({ data: mockMetrics } as any);

      const { result } = renderHook(() => useMetrics(), { wrapper: createWrapper() });

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
      expect(result.current.data?.agents.total).toBe(10);
    });
  });

  describe('useAgents', () => {
    it('should fetch agents list', async () => {
      const mockAgents = {
        agents: [{ agent_id: '123', name: 'test-agent', status: 'active' }],
        total_count: 1,
        page: 1,
        page_size: 50,
        has_more: false,
      };
      vi.mocked(apiModule.agentApi.list).mockResolvedValue({ data: mockAgents } as any);

      const { result } = renderHook(() => useAgents(1, 50), { wrapper: createWrapper() });

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
      expect(result.current.data?.agents).toHaveLength(1);
    });
  });

  describe('useAgent', () => {
    it('should fetch single agent', async () => {
      const mockAgent = {
        agent_id: '123',
        name: 'test-agent',
        status: 'active',
        tenant_id: '456',
        certificate_pem: 'cert',
        certificate_fingerprint: 'fp',
        certificate_serial: 'serial',
        certificate_subject: 'subject',
        certificate_issuer: 'issuer',
        certificate_not_before: '2025-01-01T00:00:00Z',
        certificate_not_after: '2026-01-01T00:00:00Z',
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-01T00:00:00Z',
        suspended_at: null,
        suspended_by: null,
        metadata: {},
      };
      vi.mocked(apiModule.agentApi.get).mockResolvedValue({ data: mockAgent } as any);

      const { result } = renderHook(() => useAgent('123'), { wrapper: createWrapper() });

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
      expect(result.current.data?.agent_id).toBe('123');
    });

    it('should not fetch when agentId is empty', () => {
      const { result } = renderHook(() => useAgent(''), { wrapper: createWrapper() });
      expect(result.current.fetchStatus).toBe('idle');
    });
  });

  describe('usePolicies', () => {
    it('should fetch policies list', async () => {
      const mockPolicies = {
        policies: [{ policy_id: '789', name: 'test-policy' }],
        total_count: 1,
        page: 1,
        page_size: 50,
        has_more: false,
      };
      vi.mocked(apiModule.policyApi.list).mockResolvedValue({ data: mockPolicies } as any);

      const { result } = renderHook(() => usePolicies(), { wrapper: createWrapper() });

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
      expect(result.current.data?.policies).toHaveLength(1);
    });
  });

  describe('useAuditAnalytics', () => {
    it('should fetch analytics data', async () => {
      const mockAnalytics = {
        tenant_id: '123',
        start_time: '2025-01-01T00:00:00Z',
        end_time: '2025-01-31T23:59:59Z',
        hourly_distribution: { 9: 100, 14: 150 },
        daily_distribution: { '2025-01-01': 250 },
        peak_hours: [9, 14],
        off_hours_activity_percentage: 15.5,
        weekend_activity_percentage: 8.2,
        top_domains: [{ domain: 'example.com', count: 523 }],
        anomalies: [],
        compliance_score: 92.5,
      };
      vi.mocked(apiModule.auditApi.analytics).mockResolvedValue({ data: mockAnalytics } as any);

      const { result } = renderHook(
        () => useAuditAnalytics('2025-01-01T00:00:00Z', '2025-01-31T23:59:59Z'),
        { wrapper: createWrapper() }
      );

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
      expect(result.current.data?.compliance_score).toBe(92.5);
    });

    it('should not fetch when times are empty', () => {
      const { result } = renderHook(() => useAuditAnalytics('', ''), { wrapper: createWrapper() });
      expect(result.current.fetchStatus).toBe('idle');
    });
  });
});
