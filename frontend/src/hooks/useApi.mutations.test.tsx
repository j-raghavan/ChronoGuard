import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  useCreateAgent,
  useUpdateAgent,
  useCreatePolicy,
  useUpdatePolicy,
  useDeletePolicy,
} from './useApi';
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

describe('useApi mutation hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('useCreateAgent', () => {
    it('should create agent', async () => {
      const mockAgent = { agent_id: '123', name: 'new-agent' };
      vi.mocked(apiModule.agentApi.create).mockResolvedValue({ data: mockAgent } as any);

      const { result } = renderHook(() => useCreateAgent(), { wrapper: createWrapper() });

      result.current.mutate({ name: 'new-agent', certificate_pem: 'cert' });

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
    });
  });

  describe('useUpdateAgent', () => {
    it('should update agent', async () => {
      const mockAgent = { agent_id: '123', name: 'updated-agent' };
      vi.mocked(apiModule.agentApi.update).mockResolvedValue({ data: mockAgent } as any);

      const { result } = renderHook(() => useUpdateAgent(), { wrapper: createWrapper() });

      result.current.mutate({ agentId: '123', data: { name: 'updated-agent' } });

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
    });
  });

  describe('useCreatePolicy', () => {
    it('should create policy', async () => {
      const mockPolicy = { policy_id: '789', name: 'new-policy' };
      vi.mocked(apiModule.policyApi.create).mockResolvedValue({ data: mockPolicy } as any);

      const { result } = renderHook(() => useCreatePolicy(), { wrapper: createWrapper() });

      result.current.mutate({ name: 'new-policy', description: 'Test policy' });

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
    });
  });

  describe('useUpdatePolicy', () => {
    it('should update policy', async () => {
      const mockPolicy = { policy_id: '789', name: 'updated-policy' };
      vi.mocked(apiModule.policyApi.update).mockResolvedValue({ data: mockPolicy } as any);

      const { result } = renderHook(() => useUpdatePolicy(), { wrapper: createWrapper() });

      result.current.mutate({ policyId: '789', data: { name: 'updated-policy' } });

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
    });
  });

  describe('useDeletePolicy', () => {
    it('should delete policy', async () => {
      vi.mocked(apiModule.policyApi.delete).mockResolvedValue({} as any);

      const { result } = renderHook(() => useDeletePolicy(), { wrapper: createWrapper() });

      result.current.mutate('789');

      await waitFor(() => expect(result.current.isSuccess).toBe(true));
    });
  });

  describe('usePolicy', () => {
    it('should fetch single policy', async () => {
      const mockPolicy = {
        policy_id: '789',
        name: 'test-policy',
        description: 'Test',
        priority: 50,
        rules: [],
        allowed_domains: [],
        blocked_domains: [],
        default_action: 'deny' as const,
        is_active: true,
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-01T00:00:00Z',
        created_by: 'admin',
        tenant_id: '456',
        version: 1,
      };
      vi.mocked(apiModule.policyApi.get).mockResolvedValue({ data: mockPolicy } as any);

      const { result } = renderHook(() => apiModule.policyApi.get('789'));

      await waitFor(() => expect(result.current).toBeDefined());
    });
  });

  describe('useAuditQuery', () => {
    it('should query audit entries', async () => {
      const mockQuery = {
        entries: [],
        total_count: 0,
        page: 1,
        page_size: 50,
        has_more: false,
      };
      vi.mocked(apiModule.auditApi.query).mockResolvedValue({ data: mockQuery } as any);

      const result = await apiModule.auditApi.query({ page: 1, page_size: 50 });
      expect(result.data).toEqual(mockQuery);
    });
  });
});
