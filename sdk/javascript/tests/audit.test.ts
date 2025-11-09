/**
 * Audit API test suite
 */

import { AuditAPI } from '../src/audit';
import { HttpClient } from '../src/client';
import { AuditListResponse, AccessDecision, ExportFormat } from '../src/types';

jest.mock('../src/client');

describe('AuditAPI', () => {
  let auditAPI: AuditAPI;
  let mockClient: jest.Mocked<HttpClient>;

  beforeEach(() => {
    mockClient = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn()
    } as unknown as jest.Mocked<HttpClient>;

    auditAPI = new AuditAPI(mockClient);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('query', () => {
    it('should query audit entries', async () => {
      const request = {
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        page: 1,
        page_size: 50
      };

      const expectedResponse: AuditListResponse = {
        entries: [],
        total_count: 0,
        page: 1,
        page_size: 50,
        has_more: false
      };

      mockClient.post.mockResolvedValue(expectedResponse);

      const result = await auditAPI.query(request);

      expect(mockClient.post).toHaveBeenCalledWith('/api/v1/audit/query', request);
      expect(result).toEqual(expectedResponse);
    });

    it('should query with all filters', async () => {
      const request = {
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        agent_id: '550e8400-e29b-41d4-a716-446655440002',
        domain: 'example.com',
        decision: AccessDecision.ALLOW,
        start_time: '2025-01-01T00:00:00Z',
        end_time: '2025-01-31T23:59:59Z',
        page: 1,
        page_size: 100
      };

      const expectedResponse: AuditListResponse = {
        entries: [
          {
            entry_id: '550e8400-e29b-41d4-a716-446655440003',
            tenant_id: '550e8400-e29b-41d4-a716-446655440001',
            agent_id: '550e8400-e29b-41d4-a716-446655440002',
            timestamp: '2025-01-15T14:30:00Z',
            timestamp_nanos: 1736951400000000000,
            domain: 'example.com',
            decision: AccessDecision.ALLOW,
            reason: 'Policy matched',
            policy_id: '550e8400-e29b-41d4-a716-446655440004',
            rule_id: null,
            request_method: 'GET',
            request_path: '/api/data',
            user_agent: 'Mozilla/5.0',
            source_ip: '10.0.1.5',
            response_status: 200,
            response_size_bytes: 1024,
            processing_time_ms: 12.5,
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
              quarter_of_year: 1
            },
            previous_hash: 'abc123',
            current_hash: 'def456',
            sequence_number: 1234,
            metadata: {}
          }
        ],
        total_count: 1,
        page: 1,
        page_size: 100,
        has_more: false
      };

      mockClient.post.mockResolvedValue(expectedResponse);

      const result = await auditAPI.query(request);

      expect(mockClient.post).toHaveBeenCalledWith('/api/v1/audit/query', request);
      expect(result).toEqual(expectedResponse);
      expect(result.entries).toHaveLength(1);
      expect(result.entries[0]?.decision).toBe(AccessDecision.ALLOW);
    });
  });

  describe('export', () => {
    it('should export audit entries to CSV', async () => {
      const request = {
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        start_time: '2025-01-01T00:00:00Z',
        end_time: '2025-01-31T23:59:59Z',
        format: ExportFormat.CSV
      };

      const csvData = 'entry_id,timestamp,domain,decision\n1,2025-01-15,example.com,allow';
      const blob = new Blob([csvData], { type: 'text/csv' });

      mockClient.post.mockResolvedValue(blob as never);

      const result = await auditAPI.export(request);

      expect(mockClient.post).toHaveBeenCalledWith(
        '/api/v1/audit/export',
        request,
        { responseType: 'blob' }
      );
      expect(result).toBe(csvData);
    });

    it('should export audit entries to JSON', async () => {
      const request = {
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        start_time: '2025-01-01T00:00:00Z',
        end_time: '2025-01-31T23:59:59Z',
        format: ExportFormat.JSON,
        pretty_json: true
      };

      const jsonData = JSON.stringify([{ entry_id: '1', domain: 'example.com' }], null, 2);
      const blob = new Blob([jsonData], { type: 'application/json' });

      mockClient.post.mockResolvedValue(blob as never);

      const result = await auditAPI.export(request);

      expect(mockClient.post).toHaveBeenCalledWith(
        '/api/v1/audit/export',
        request,
        { responseType: 'blob' }
      );
      expect(result).toBe(jsonData);
    });

    it('should handle string response', async () => {
      const request = {
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        start_time: '2025-01-01T00:00:00Z',
        end_time: '2025-01-31T23:59:59Z',
        format: ExportFormat.CSV
      };

      const csvData = 'entry_id,timestamp\n1,2025-01-15';

      mockClient.post.mockResolvedValue(csvData as never);

      const result = await auditAPI.export(request);

      expect(result).toBe(csvData);
    });
  });
});
