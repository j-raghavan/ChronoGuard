/**
 * ChronoGuard Audit Log API
 *
 * Provides methods for querying and exporting audit logs.
 */

import { HttpClient } from './client';
import {
  AuditListResponse,
  AuditQueryRequest,
  AuditExportRequest
} from './types';

/**
 * Audit log API client
 */
export class AuditAPI {
  private readonly client: HttpClient;

  constructor(client: HttpClient) {
    this.client = client;
  }

  /**
   * Query audit log entries with filtering and pagination
   *
   * @param request - Query request with filters
   * @returns Paginated list of audit entries
   *
   * @throws {ValidationError} If query parameters are invalid
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * const response = await client.audit.query({
   *   tenant_id: '550e8400-e29b-41d4-a716-446655440001',
   *   agent_id: '550e8400-e29b-41d4-a716-446655440002',
   *   decision: 'allow',
   *   start_time: '2025-01-01T00:00:00Z',
   *   end_time: '2025-01-31T23:59:59Z',
   *   page: 1,
   *   page_size: 50
   * });
   * console.log(`Total entries: ${response.total_count}`);
   * response.entries.forEach(entry => {
   *   console.log(`${entry.timestamp}: ${entry.decision} - ${entry.domain}`);
   * });
   * ```
   */
  async query(request: AuditQueryRequest): Promise<AuditListResponse> {
    return this.client.post<AuditListResponse, AuditQueryRequest>('/api/v1/audit/query', request);
  }

  /**
   * Export audit log entries to CSV or JSON format
   *
   * @param request - Export request with time range and format
   * @returns Exported data as string (CSV or JSON)
   *
   * @throws {ValidationError} If request is invalid
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * // Export to CSV
   * const csvData = await client.audit.export({
   *   tenant_id: '550e8400-e29b-41d4-a716-446655440001',
   *   start_time: '2025-01-01T00:00:00Z',
   *   end_time: '2025-01-31T23:59:59Z',
   *   format: 'csv'
   * });
   * console.log(csvData);
   *
   * // Export to JSON
   * const jsonData = await client.audit.export({
   *   tenant_id: '550e8400-e29b-41d4-a716-446655440001',
   *   start_time: '2025-01-01T00:00:00Z',
   *   end_time: '2025-01-31T23:59:59Z',
   *   format: 'json',
   *   pretty_json: true
   * });
   * const entries = JSON.parse(jsonData);
   * console.log(entries);
   * ```
   */
  async export(request: AuditExportRequest): Promise<string> {
    // Make request with custom response type to get raw data
    const response = await this.client.post<Blob, AuditExportRequest>(
      '/api/v1/audit/export',
      request,
      {
        responseType: 'blob'
      }
    );

    // Convert blob to string
    if (response instanceof Blob) {
      return await response.text();
    }

    // If response is already a string (shouldn't happen but handle it)
    return String(response);
  }
}
