/**
 * Policy API test suite
 */

import { PolicyAPI } from '../src/policies';
import { HttpClient } from '../src/client';
import { Policy, PolicyListResponse, PolicyStatus } from '../src/types';

jest.mock('../src/client');

describe('PolicyAPI', () => {
  let policyAPI: PolicyAPI;
  let mockClient: jest.Mocked<HttpClient>;

  beforeEach(() => {
    mockClient = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn()
    } as unknown as jest.Mocked<HttpClient>;

    policyAPI = new PolicyAPI(mockClient);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    it('should create a policy', async () => {
      const request = {
        name: 'test-policy',
        description: 'Test policy description',
        priority: 500,
        allowed_domains: ['example.com'],
        blocked_domains: [],
        metadata: { env: 'test' }
      };

      const expectedResponse: Policy = {
        policy_id: '550e8400-e29b-41d4-a716-446655440000',
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        name: 'test-policy',
        description: 'Test policy description',
        rules: [],
        time_restrictions: null,
        rate_limits: null,
        priority: 500,
        status: PolicyStatus.ACTIVE,
        allowed_domains: ['example.com'],
        blocked_domains: [],
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-01T00:00:00Z',
        created_by: '550e8400-e29b-41d4-a716-446655440002',
        version: 1,
        metadata: { env: 'test' }
      };

      mockClient.post.mockResolvedValue(expectedResponse);

      const result = await policyAPI.create(request);

      expect(mockClient.post).toHaveBeenCalledWith('/api/v1/policies/', request);
      expect(result).toEqual(expectedResponse);
    });
  });

  describe('get', () => {
    it('should get a policy by ID', async () => {
      const policyId = '550e8400-e29b-41d4-a716-446655440000';
      const expectedResponse: Policy = {
        policy_id: policyId,
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        name: 'test-policy',
        description: 'Test policy',
        rules: [],
        time_restrictions: null,
        rate_limits: null,
        priority: 500,
        status: PolicyStatus.ACTIVE,
        allowed_domains: ['example.com'],
        blocked_domains: [],
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-01T00:00:00Z',
        created_by: '550e8400-e29b-41d4-a716-446655440002',
        version: 1,
        metadata: {}
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await policyAPI.get(policyId);

      expect(mockClient.get).toHaveBeenCalledWith(`/api/v1/policies/${policyId}`);
      expect(result).toEqual(expectedResponse);
    });
  });

  describe('list', () => {
    it('should list policies with default options', async () => {
      const expectedResponse: PolicyListResponse = {
        policies: [],
        total_count: 0,
        page: 1,
        page_size: 50
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await policyAPI.list();

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/policies/', { params: {} });
      expect(result).toEqual(expectedResponse);
    });

    it('should list policies with pagination', async () => {
      const expectedResponse: PolicyListResponse = {
        policies: [],
        total_count: 100,
        page: 2,
        page_size: 25
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await policyAPI.list({ page: 2, page_size: 25 });

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/policies/', {
        params: { page: 2, page_size: 25 }
      });
      expect(result).toEqual(expectedResponse);
    });

    it('should list policies with status filter', async () => {
      const expectedResponse: PolicyListResponse = {
        policies: [],
        total_count: 10,
        page: 1,
        page_size: 50
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await policyAPI.list({ status_filter: PolicyStatus.ACTIVE });

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/policies/', {
        params: { status_filter: PolicyStatus.ACTIVE }
      });
      expect(result).toEqual(expectedResponse);
    });

    it('should list policies with all options', async () => {
      const expectedResponse: PolicyListResponse = {
        policies: [],
        total_count: 5,
        page: 3,
        page_size: 10
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await policyAPI.list({
        page: 3,
        page_size: 10,
        status_filter: PolicyStatus.INACTIVE
      });

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/policies/', {
        params: {
          page: 3,
          page_size: 10,
          status_filter: PolicyStatus.INACTIVE
        }
      });
      expect(result).toEqual(expectedResponse);
    });
  });

  describe('update', () => {
    it('should update a policy', async () => {
      const policyId = '550e8400-e29b-41d4-a716-446655440000';
      const request = {
        name: 'updated-policy',
        description: 'Updated description',
        priority: 600
      };

      const expectedResponse: Policy = {
        policy_id: policyId,
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        name: 'updated-policy',
        description: 'Updated description',
        rules: [],
        time_restrictions: null,
        rate_limits: null,
        priority: 600,
        status: PolicyStatus.ACTIVE,
        allowed_domains: ['example.com'],
        blocked_domains: [],
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-15T12:00:00Z',
        created_by: '550e8400-e29b-41d4-a716-446655440002',
        version: 2,
        metadata: {}
      };

      mockClient.put.mockResolvedValue(expectedResponse);

      const result = await policyAPI.update(policyId, request);

      expect(mockClient.put).toHaveBeenCalledWith(`/api/v1/policies/${policyId}`, request);
      expect(result).toEqual(expectedResponse);
    });

    it('should update policy domains', async () => {
      const policyId = '550e8400-e29b-41d4-a716-446655440000';
      const request = {
        allowed_domains: ['new.example.com', 'test.example.com'],
        blocked_domains: ['bad.example.com']
      };

      const expectedResponse: Policy = {
        policy_id: policyId,
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        name: 'test-policy',
        description: 'Test policy',
        rules: [],
        time_restrictions: null,
        rate_limits: null,
        priority: 500,
        status: PolicyStatus.ACTIVE,
        allowed_domains: ['new.example.com', 'test.example.com'],
        blocked_domains: ['bad.example.com'],
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-15T12:00:00Z',
        created_by: '550e8400-e29b-41d4-a716-446655440002',
        version: 2,
        metadata: {}
      };

      mockClient.put.mockResolvedValue(expectedResponse);

      const result = await policyAPI.update(policyId, request);

      expect(mockClient.put).toHaveBeenCalledWith(`/api/v1/policies/${policyId}`, request);
      expect(result).toEqual(expectedResponse);
    });
  });

  describe('delete', () => {
    it('should delete a policy', async () => {
      const policyId = '550e8400-e29b-41d4-a716-446655440000';

      mockClient.delete.mockResolvedValue(undefined);

      await policyAPI.delete(policyId);

      expect(mockClient.delete).toHaveBeenCalledWith(`/api/v1/policies/${policyId}`);
    });

    it('should return void on successful delete', async () => {
      const policyId = '550e8400-e29b-41d4-a716-446655440000';

      mockClient.delete.mockResolvedValue(undefined);

      const result = await policyAPI.delete(policyId);

      expect(result).toBeUndefined();
    });
  });
});
