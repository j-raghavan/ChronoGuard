/**
 * API client for ChronoGuard backend
 * Uses axios for HTTP requests with TypeScript types
 * Supports swapping to Mock Implementation for zero-install demos
 */

import axios from "axios";
import type { AxiosInstance } from "axios";
import type {
  AgentDTO,
  AgentListResponse,
  CreateAgentRequest,
  UpdateAgentRequest,
  PolicyDTO,
  PolicyListResponse,
  CreatePolicyRequest,
  UpdatePolicyRequest,
  AuditListResponse,
  AuditQueryRequest,
  TemporalPatternDTO,
  MetricsSummaryResponse,
  HealthResponse,
  LoginResponse,
  SessionResponse,
} from "@/types/api";

import { mockApi } from "./mockApi";

// Check environment variable to determine if we should use mocks
const USE_MOCK_API = import.meta.env.VITE_USE_MOCK_API === "true";

// Use relative URL (empty string) for production/Codespaces (nginx proxies /api/* to backend)
// Use VITE_API_URL only for local development with separate backend
const API_BASE_URL = import.meta.env.VITE_API_URL || "";

// Create axios instance with default configuration
const createApiClient = (): AxiosInstance => {
  const client = axios.create({
    baseURL: API_BASE_URL,
    withCredentials: true,
    headers: {
      "Content-Type": "application/json",
    },
  });

  // Request interceptor to add authentication headers
  client.interceptors.request.use(
    (config) => {
      // Get token from localStorage and add to Authorization header
      const token = localStorage.getItem("access_token");
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    },
    (error) => Promise.reject(error),
  );

  // Response interceptor for error handling
  client.interceptors.response.use(
    (response) => response,
    (error) => {
      // Don't redirect on 401 for session check or login endpoints
      // These are expected to return 401 when not authenticated
      const isAuthEndpoint = error.config?.url?.includes("/api/v1/auth/");
      if (error.response?.status === 401 && !isAuthEndpoint) {
        // Handle unauthorized - clear auth and redirect to login
        console.error("Unauthorized access - clearing authentication");
        window.location.href = "/";
      }
      return Promise.reject(error);
    },
  );

  return client;
};

const axiosClient = createApiClient();

// Auth Endpoints
export const authApi = {
  login: (password: string) =>
    USE_MOCK_API
      ? mockApi.auth.login()
      : axiosClient.post<LoginResponse>("/api/v1/auth/login", { password }),

  logout: () =>
    USE_MOCK_API
      ? mockApi.auth.logout()
      : axiosClient.post<void>("/api/v1/auth/logout", {}),

  session: () =>
    USE_MOCK_API
      ? mockApi.auth.session()
      : axiosClient.get<SessionResponse>("/api/v1/auth/session"),
};

// Health Endpoints
export const healthApi = {
  check: () =>
    USE_MOCK_API
      ? mockApi.health.check()
      : axiosClient.get<HealthResponse>("/api/v1/health/"),

  ready: () =>
    USE_MOCK_API
      ? mockApi.health.ready()
      : axiosClient.get<HealthResponse>("/api/v1/health/ready"),

  metrics: () =>
    USE_MOCK_API
      ? mockApi.health.metrics()
      : axiosClient.get<MetricsSummaryResponse>("/api/v1/health/metrics"),
};

// Agent Endpoints
export const agentApi = {
  list: (page = 1, pageSize = 50) =>
    USE_MOCK_API
      ? mockApi.agents.list(page, pageSize)
      : axiosClient.get<AgentListResponse>("/api/v1/agents/", {
          params: { page, page_size: pageSize },
        }),

  get: (agentId: string) =>
    USE_MOCK_API
      ? mockApi.agents.get(agentId)
      : axiosClient.get<AgentDTO>(`/api/v1/agents/${agentId}`),

  create: (data: CreateAgentRequest) =>
    USE_MOCK_API
      ? mockApi.agents.create(data)
      : axiosClient.post<AgentDTO>("/api/v1/agents/", data),

  update: (agentId: string, data: UpdateAgentRequest) =>
    USE_MOCK_API
      ? mockApi.agents.update(agentId, data)
      : axiosClient.put<AgentDTO>(`/api/v1/agents/${agentId}`, data),
};

// Policy Endpoints
export const policyApi = {
  list: (page = 1, pageSize = 50) =>
    USE_MOCK_API
      ? mockApi.policies.list(page, pageSize)
      : axiosClient.get<PolicyListResponse>("/api/v1/policies/", {
          params: { page, page_size: pageSize },
        }),

  get: (policyId: string) =>
    USE_MOCK_API
      ? mockApi.policies.get(policyId)
      : axiosClient.get<PolicyDTO>(`/api/v1/policies/${policyId}`),

  create: (data: CreatePolicyRequest) =>
    USE_MOCK_API
      ? mockApi.policies.create(data)
      : axiosClient.post<PolicyDTO>("/api/v1/policies/", data),

  update: (policyId: string, data: UpdatePolicyRequest) =>
    USE_MOCK_API
      ? mockApi.policies.update(policyId, data)
      : axiosClient.put<PolicyDTO>(`/api/v1/policies/${policyId}`, data),

  delete: (policyId: string) =>
    USE_MOCK_API
      ? mockApi.policies.delete(policyId)
      : axiosClient.delete(`/api/v1/policies/${policyId}`),
};

// Audit Endpoints
export const auditApi = {
  query: (params: AuditQueryRequest) =>
    USE_MOCK_API
      ? mockApi.audit.query(params)
      : axiosClient.post<AuditListResponse>("/api/v1/audit/query", params),

  analytics: (startTime: string, endTime: string) =>
    USE_MOCK_API
      ? mockApi.audit.analytics(startTime, endTime)
      : axiosClient.get<TemporalPatternDTO>("/api/v1/audit/analytics", {
          params: {
            start_time: startTime,
            end_time: endTime,
          },
        }),

  export: (format: "csv" | "json", startTime: string, endTime: string) => {
    if (USE_MOCK_API) return mockApi.audit.export();

    return axiosClient.post(
      "/api/v1/audit/export",
      {
        start_time: startTime,
        end_time: endTime,
        format,
      },
      {
        responseType: "blob",
      },
    );
  },
};

export { axiosClient as apiClient };
