/**
 * React Query hooks for API calls
 * Provides typed hooks with caching and error handling
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { agentApi, policyApi, auditApi, healthApi } from "@/services/api";
import type {
  CreateAgentRequest,
  UpdateAgentRequest,
  CreatePolicyRequest,
  UpdatePolicyRequest,
  AuditQueryRequest,
} from "@/types/api";

// Query Keys
export const queryKeys = {
  health: ["health"] as const,
  metrics: ["metrics"] as const,
  agents: {
    all: ["agents"] as const,
    list: (page: number) => ["agents", "list", page] as const,
    detail: (id: string) => ["agents", "detail", id] as const,
  },
  policies: {
    all: ["policies"] as const,
    list: (page: number) => ["policies", "list", page] as const,
    detail: (id: string) => ["policies", "detail", id] as const,
  },
  audit: {
    all: ["audit"] as const,
    query: (params: AuditQueryRequest) => ["audit", "query", params] as const,
    analytics: (start: string, end: string) =>
      ["audit", "analytics", start, end] as const,
  },
};

// Health Hooks
export const useHealth = () => {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: async () => (await healthApi.check()).data,
    staleTime: 30000, // 30 seconds
  });
};

export const useMetrics = () => {
  return useQuery({
    queryKey: queryKeys.metrics,
    queryFn: async () => (await healthApi.metrics()).data,
    refetchInterval: 30000, // Refresh every 30 seconds
  });
};

// Agent Hooks
export const useAgents = (page = 1, pageSize = 50) => {
  return useQuery({
    queryKey: queryKeys.agents.list(page),
    queryFn: async () => (await agentApi.list(page, pageSize)).data,
    staleTime: 60000, // 1 minute
  });
};

export const useAgent = (agentId: string) => {
  return useQuery({
    queryKey: queryKeys.agents.detail(agentId),
    queryFn: async () => (await agentApi.get(agentId)).data,
    enabled: !!agentId,
  });
};

export const useCreateAgent = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateAgentRequest) => agentApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agents.all });
    },
  });
};

export const useUpdateAgent = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      agentId,
      data,
    }: {
      agentId: string;
      data: UpdateAgentRequest;
    }) => agentApi.update(agentId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agents.all });
    },
  });
};

// Policy Hooks
export const usePolicies = (page = 1, pageSize = 50) => {
  return useQuery({
    queryKey: queryKeys.policies.list(page),
    queryFn: async () => (await policyApi.list(page, pageSize)).data,
    staleTime: 60000, // 1 minute
  });
};

export const usePolicy = (policyId: string) => {
  return useQuery({
    queryKey: queryKeys.policies.detail(policyId),
    queryFn: async () => (await policyApi.get(policyId)).data,
    enabled: !!policyId,
  });
};

export const useCreatePolicy = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreatePolicyRequest) => policyApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.all });
    },
  });
};

export const useUpdatePolicy = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      policyId,
      data,
    }: {
      policyId: string;
      data: UpdatePolicyRequest;
    }) => policyApi.update(policyId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.all });
    },
  });
};

export const useDeletePolicy = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (policyId: string) => policyApi.delete(policyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.all });
    },
  });
};

// Audit Hooks
export const useAuditQuery = (params: AuditQueryRequest) => {
  return useQuery({
    queryKey: queryKeys.audit.query(params),
    queryFn: async () => (await auditApi.query(params)).data,
    staleTime: 30000, // 30 seconds
  });
};

export const useAuditAnalytics = (startTime: string, endTime: string) => {
  return useQuery({
    queryKey: queryKeys.audit.analytics(startTime, endTime),
    queryFn: async () => (await auditApi.analytics(startTime, endTime)).data,
    staleTime: 300000, // 5 minutes
    enabled: !!startTime && !!endTime,
  });
};
