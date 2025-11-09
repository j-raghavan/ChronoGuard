/**
 * Agent API test suite
 */

import { AgentAPI } from '../src/agents';
import { HttpClient } from '../src/client';
import { Agent, AgentListResponse, AgentStatus } from '../src/types';

jest.mock('../src/client');

describe('AgentAPI', () => {
  let agentAPI: AgentAPI;
  let mockClient: jest.Mocked<HttpClient>;

  beforeEach(() => {
    mockClient = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn()
    } as unknown as jest.Mocked<HttpClient>;

    agentAPI = new AgentAPI(mockClient);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    it('should create an agent', async () => {
      const request = {
        name: 'test-agent',
        certificate_pem: '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
        metadata: { env: 'test' }
      };

      const expectedResponse: Agent = {
        agent_id: '550e8400-e29b-41d4-a716-446655440000',
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        name: 'test-agent',
        status: AgentStatus.ACTIVE,
        certificate_fingerprint: 'sha256:abc123',
        certificate_subject: 'CN=test-agent',
        certificate_expiry: '2025-12-31T23:59:59Z',
        policy_ids: [],
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-01T00:00:00Z',
        last_seen_at: null,
        metadata: { env: 'test' },
        version: 1
      };

      mockClient.post.mockResolvedValue(expectedResponse);

      const result = await agentAPI.create(request);

      expect(mockClient.post).toHaveBeenCalledWith('/api/v1/agents/', request);
      expect(result).toEqual(expectedResponse);
    });
  });

  describe('get', () => {
    it('should get an agent by ID', async () => {
      const agentId = '550e8400-e29b-41d4-a716-446655440000';
      const expectedResponse: Agent = {
        agent_id: agentId,
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        name: 'test-agent',
        status: AgentStatus.ACTIVE,
        certificate_fingerprint: 'sha256:abc123',
        certificate_subject: 'CN=test-agent',
        certificate_expiry: '2025-12-31T23:59:59Z',
        policy_ids: [],
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-01T00:00:00Z',
        last_seen_at: '2025-01-15T10:00:00Z',
        metadata: {},
        version: 1
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await agentAPI.get(agentId);

      expect(mockClient.get).toHaveBeenCalledWith(`/api/v1/agents/${agentId}`);
      expect(result).toEqual(expectedResponse);
    });
  });

  describe('list', () => {
    it('should list agents with default options', async () => {
      const expectedResponse: AgentListResponse = {
        agents: [],
        total_count: 0,
        page: 1,
        page_size: 50
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await agentAPI.list();

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/agents/', { params: {} });
      expect(result).toEqual(expectedResponse);
    });

    it('should list agents with pagination', async () => {
      const expectedResponse: AgentListResponse = {
        agents: [],
        total_count: 100,
        page: 2,
        page_size: 25
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await agentAPI.list({ page: 2, page_size: 25 });

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/agents/', {
        params: { page: 2, page_size: 25 }
      });
      expect(result).toEqual(expectedResponse);
    });

    it('should list agents with status filter', async () => {
      const expectedResponse: AgentListResponse = {
        agents: [],
        total_count: 10,
        page: 1,
        page_size: 50
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await agentAPI.list({ status_filter: AgentStatus.ACTIVE });

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/agents/', {
        params: { status_filter: AgentStatus.ACTIVE }
      });
      expect(result).toEqual(expectedResponse);
    });

    it('should list agents with all options', async () => {
      const expectedResponse: AgentListResponse = {
        agents: [],
        total_count: 5,
        page: 3,
        page_size: 10
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await agentAPI.list({
        page: 3,
        page_size: 10,
        status_filter: AgentStatus.SUSPENDED
      });

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/agents/', {
        params: {
          page: 3,
          page_size: 10,
          status_filter: AgentStatus.SUSPENDED
        }
      });
      expect(result).toEqual(expectedResponse);
    });
  });

  describe('update', () => {
    it('should update an agent', async () => {
      const agentId = '550e8400-e29b-41d4-a716-446655440000';
      const request = {
        name: 'updated-agent',
        metadata: { env: 'production' }
      };

      const expectedResponse: Agent = {
        agent_id: agentId,
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        name: 'updated-agent',
        status: AgentStatus.ACTIVE,
        certificate_fingerprint: 'sha256:abc123',
        certificate_subject: 'CN=test-agent',
        certificate_expiry: '2025-12-31T23:59:59Z',
        policy_ids: [],
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-15T12:00:00Z',
        last_seen_at: null,
        metadata: { env: 'production' },
        version: 2
      };

      mockClient.put.mockResolvedValue(expectedResponse);

      const result = await agentAPI.update(agentId, request);

      expect(mockClient.put).toHaveBeenCalledWith(`/api/v1/agents/${agentId}`, request);
      expect(result).toEqual(expectedResponse);
    });

    it('should update agent with certificate', async () => {
      const agentId = '550e8400-e29b-41d4-a716-446655440000';
      const request = {
        certificate_pem: '-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----'
      };

      const expectedResponse: Agent = {
        agent_id: agentId,
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        name: 'test-agent',
        status: AgentStatus.ACTIVE,
        certificate_fingerprint: 'sha256:def456',
        certificate_subject: 'CN=test-agent',
        certificate_expiry: '2026-12-31T23:59:59Z',
        policy_ids: [],
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-15T12:00:00Z',
        last_seen_at: null,
        metadata: {},
        version: 2
      };

      mockClient.put.mockResolvedValue(expectedResponse);

      const result = await agentAPI.update(agentId, request);

      expect(mockClient.put).toHaveBeenCalledWith(`/api/v1/agents/${agentId}`, request);
      expect(result).toEqual(expectedResponse);
    });
  });
});
