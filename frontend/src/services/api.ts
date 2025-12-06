/**
 * API client for ChronoGuard backend
 * Uses axios for HTTP requests with TypeScript types
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
      if (error.response?.status === 401) {
        // Handle unauthorized - clear auth and redirect to login
        console.error("Unauthorized access - clearing authentication");
        window.location.href = "/";
      }
      return Promise.reject(error);
    },
  );

  return client;
};

const apiClient = createApiClient();

// Auth Endpoints
export const authApi = {
  login: (password: string) =>
    apiClient.post<LoginResponse>("/api/v1/auth/login", {
      password,
    }),
  logout: () => apiClient.post<void>("/api/v1/auth/logout", {}),
  session: () => apiClient.get<SessionResponse>("/api/v1/auth/session"),
};

// Health Endpoints
export const healthApi = {
  check: () => apiClient.get<HealthResponse>("/api/v1/health/"),
  ready: () => apiClient.get<HealthResponse>("/api/v1/health/ready"),
  metrics: () =>
    apiClient.get<MetricsSummaryResponse>("/api/v1/health/metrics"),
};

// Agent Endpoints
export const agentApi = {
  list: (page = 1, pageSize = 50) =>
    apiClient.get<AgentListResponse>("/api/v1/agents/", {
      params: { page, page_size: pageSize },
    }),

  get: (agentId: string) =>
    apiClient.get<AgentDTO>(`/api/v1/agents/${agentId}`),

  create: (data: CreateAgentRequest) =>
    apiClient.post<AgentDTO>("/api/v1/agents/", data),

  update: (agentId: string, data: UpdateAgentRequest) =>
    apiClient.put<AgentDTO>(`/api/v1/agents/${agentId}`, data),
};

// Policy Endpoints
export const policyApi = {
  list: (page = 1, pageSize = 50) =>
    apiClient.get<PolicyListResponse>("/api/v1/policies/", {
      params: { page, page_size: pageSize },
    }),

  get: (policyId: string) =>
    apiClient.get<PolicyDTO>(`/api/v1/policies/${policyId}`),

  create: (data: CreatePolicyRequest) =>
    apiClient.post<PolicyDTO>("/api/v1/policies/", data),

  update: (policyId: string, data: UpdatePolicyRequest) =>
    apiClient.put<PolicyDTO>(`/api/v1/policies/${policyId}`, data),

  delete: (policyId: string) =>
    apiClient.delete(`/api/v1/policies/${policyId}`),
};

// Audit Endpoints
export const auditApi = {
  query: (params: AuditQueryRequest) =>
    apiClient.post<AuditListResponse>("/api/v1/audit/query", params),

  analytics: (startTime: string, endTime: string) =>
    apiClient.get<TemporalPatternDTO>("/api/v1/audit/analytics", {
      params: {
        start_time: startTime,
        end_time: endTime,
      },
    }),

  export: (format: "csv" | "json", startTime: string, endTime: string) => {
    return apiClient.post(
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

export { apiClient };
