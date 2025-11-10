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
} from "@/types/api";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

// Create axios instance with default configuration
const createApiClient = (): AxiosInstance => {
  const client = axios.create({
    baseURL: API_BASE_URL,
    headers: {
      "Content-Type": "application/json",
    },
  });

  // Request interceptor to add authentication headers
  client.interceptors.request.use(
    (config) => {
      const tenantId = localStorage.getItem("tenantId");
      const userId = localStorage.getItem("userId");
      const token = localStorage.getItem("authToken");
      const expiresAt = localStorage.getItem("tokenExpiresAt");

      // Check token expiration before request
      if (expiresAt && parseInt(expiresAt) < Date.now()) {
        // Token expired - clear auth state
        localStorage.removeItem("authToken");
        localStorage.removeItem("tokenExpiresAt");
        localStorage.removeItem("isAuthenticated");
        localStorage.removeItem("tenantId");
        localStorage.removeItem("userId");
        window.location.href = "/";
        return Promise.reject(new Error("Token expired"));
      }

      if (tenantId) {
        config.headers["X-Tenant-ID"] = tenantId;
      }
      if (userId) {
        config.headers["X-User-ID"] = userId;
      }
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
        localStorage.removeItem("authToken");
        localStorage.removeItem("tokenExpiresAt");
        localStorage.removeItem("isAuthenticated");
        localStorage.removeItem("tenantId");
        localStorage.removeItem("userId");
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
    const tenantId = localStorage.getItem("tenantId");
    return apiClient.post(
      "/api/v1/audit/export",
      {
        tenant_id: tenantId,
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
