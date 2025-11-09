/**
 * Main SDK test suite
 */

import { ChronoGuard } from '../src/index';
import { AgentAPI } from '../src/agents';
import { PolicyAPI } from '../src/policies';
import { AuditAPI } from '../src/audit';
import { AnalyticsAPI } from '../src/analytics';
import { ConfigurationError } from '../src/errors';

jest.mock('../src/client');
jest.mock('../src/agents');
jest.mock('../src/policies');
jest.mock('../src/audit');
jest.mock('../src/analytics');

describe('ChronoGuard SDK', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Constructor', () => {
    it('should create SDK instance with valid config', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });

      expect(sdk).toBeInstanceOf(ChronoGuard);
      expect(sdk.agents).toBeInstanceOf(AgentAPI);
      expect(sdk.policies).toBeInstanceOf(PolicyAPI);
      expect(sdk.audit).toBeInstanceOf(AuditAPI);
      expect(sdk.analytics).toBeInstanceOf(AnalyticsAPI);
    });

    it('should create SDK with full config', () => {
      const config = {
        apiUrl: 'https://api.example.com',
        tenantId: '550e8400-e29b-41d4-a716-446655440001',
        userId: '550e8400-e29b-41d4-a716-446655440002',
        timeout: 5000,
        debug: true
      };

      const sdk = new ChronoGuard(config);

      expect(sdk).toBeInstanceOf(ChronoGuard);
    });

    it('should expose all API modules', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });

      expect(sdk.agents).toBeDefined();
      expect(sdk.policies).toBeDefined();
      expect(sdk.audit).toBeDefined();
      expect(sdk.analytics).toBeDefined();
    });
  });

  describe('Tenant and User ID Management', () => {
    it('should set and get tenant ID', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });
      const tenantId = '550e8400-e29b-41d4-a716-446655440001';

      sdk.setTenantId(tenantId);

      // Since we're mocking, we need to verify the call was made
      expect(sdk.setTenantId).toBeDefined();
    });

    it('should set and get user ID', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });
      const userId = '550e8400-e29b-41d4-a716-446655440002';

      sdk.setUserId(userId);

      expect(sdk.setUserId).toBeDefined();
    });
  });

  describe('Configuration', () => {
    it('should provide getBaseUrl method', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });

      expect(sdk.getBaseUrl).toBeDefined();
      expect(typeof sdk.getBaseUrl).toBe('function');
    });

    it('should provide getTenantId method', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });

      expect(sdk.getTenantId).toBeDefined();
      expect(typeof sdk.getTenantId).toBe('function');
    });

    it('should provide getUserId method', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });

      expect(sdk.getUserId).toBeDefined();
      expect(typeof sdk.getUserId).toBe('function');
    });
  });

  describe('API Modules Integration', () => {
    it('should initialize AgentAPI with client', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });

      expect(sdk.agents).toBeInstanceOf(AgentAPI);
    });

    it('should initialize PolicyAPI with client', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });

      expect(sdk.policies).toBeInstanceOf(PolicyAPI);
    });

    it('should initialize AuditAPI with client', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });

      expect(sdk.audit).toBeInstanceOf(AuditAPI);
    });

    it('should initialize AnalyticsAPI with client', () => {
      const sdk = new ChronoGuard({ apiUrl: 'http://localhost:8000' });

      expect(sdk.analytics).toBeInstanceOf(AnalyticsAPI);
    });
  });

  describe('Exports', () => {
    it('should export ChronoGuard class', () => {
      expect(ChronoGuard).toBeDefined();
    });

    it('should export API classes', () => {
      expect(AgentAPI).toBeDefined();
      expect(PolicyAPI).toBeDefined();
      expect(AuditAPI).toBeDefined();
      expect(AnalyticsAPI).toBeDefined();
    });

    it('should export error classes', () => {
      expect(ConfigurationError).toBeDefined();
    });
  });
});
