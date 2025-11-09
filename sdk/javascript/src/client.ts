/**
 * ChronoGuard HTTP Client
 *
 * Core HTTP client implementation using axios for all API communication.
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import {
  ChronoGuardConfig,
  UUID
} from './types';
import {
  createErrorFromResponse,
  NetworkError,
  TimeoutError,
  ConfigurationError
} from './errors';

/**
 * HTTP Client for ChronoGuard API
 */
export class HttpClient {
  private readonly axiosInstance: AxiosInstance;
  private readonly config: Required<Pick<ChronoGuardConfig, 'apiUrl' | 'timeout' | 'debug'>> & ChronoGuardConfig;

  constructor(config: ChronoGuardConfig) {
    // Validate configuration
    if (!config.apiUrl) {
      throw new ConfigurationError('apiUrl is required');
    }

    if (!config.apiUrl.startsWith('http://') && !config.apiUrl.startsWith('https://')) {
      throw new ConfigurationError('apiUrl must start with http:// or https://');
    }

    this.config = {
      timeout: 30000,
      debug: false,
      ...config
    };

    // Create axios instance
    this.axiosInstance = axios.create({
      baseURL: this.config.apiUrl,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        ...this.config.headers
      }
    });

    // Add request interceptor for logging and headers
    this.axiosInstance.interceptors.request.use(
      (requestConfig) => {
        if (this.config.debug) {
          console.log(`[ChronoGuard] ${requestConfig.method?.toUpperCase()} ${requestConfig.url}`);
        }

        // Add tenant ID header if configured
        if (this.config.tenantId && requestConfig.headers) {
          requestConfig.headers['X-Tenant-ID'] = this.config.tenantId;
        }

        // Add user ID header if configured
        if (this.config.userId && requestConfig.headers) {
          requestConfig.headers['X-User-ID'] = this.config.userId;
        }

        return requestConfig;
      },
      (error: AxiosError) => {
        return Promise.reject(error);
      }
    );

    // Add response interceptor for error handling
    this.axiosInstance.interceptors.response.use(
      (response) => {
        if (this.config.debug) {
          console.log(`[ChronoGuard] Response ${response.status} from ${response.config.url}`);
        }
        return response;
      },
      (error: AxiosError) => {
        return Promise.reject(this.handleError(error));
      }
    );
  }

  /**
   * Handle and transform axios errors into ChronoGuard errors
   */
  private handleError(error: AxiosError): Error {
    if (this.config.debug) {
      console.error('[ChronoGuard] Error:', error.message);
    }

    // Network errors (no response)
    if (!error.response) {
      if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
        return new TimeoutError('Request timeout', { originalError: error.message });
      }
      return new NetworkError(
        error.message || 'Network error occurred',
        { originalError: error.message }
      );
    }

    // HTTP errors (with response)
    const statusCode = error.response.status;
    const responseData = error.response.data as { detail?: string } | undefined;
    const message = responseData?.detail || error.message || `HTTP ${statusCode} error`;

    return createErrorFromResponse(statusCode, message, responseData);
  }

  /**
   * Perform GET request
   */
  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<T> = await this.axiosInstance.get(url, config);
    return response.data;
  }

  /**
   * Perform POST request
   */
  async post<T, D = unknown>(url: string, data?: D, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<T> = await this.axiosInstance.post(url, data, config);
    return response.data;
  }

  /**
   * Perform PUT request
   */
  async put<T, D = unknown>(url: string, data?: D, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<T> = await this.axiosInstance.put(url, data, config);
    return response.data;
  }

  /**
   * Perform DELETE request
   */
  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<T> = await this.axiosInstance.delete(url, config);
    return response.data;
  }

  /**
   * Update tenant ID for subsequent requests
   */
  setTenantId(tenantId: UUID): void {
    this.config.tenantId = tenantId;
  }

  /**
   * Update user ID for subsequent requests
   */
  setUserId(userId: UUID): void {
    this.config.userId = userId;
  }

  /**
   * Get current tenant ID
   */
  getTenantId(): UUID | undefined {
    return this.config.tenantId;
  }

  /**
   * Get current user ID
   */
  getUserId(): UUID | undefined {
    return this.config.userId;
  }

  /**
   * Get API base URL
   */
  getBaseUrl(): string {
    return this.config.apiUrl;
  }
}
