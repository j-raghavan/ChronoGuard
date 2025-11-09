/**
 * Analytics API test suite
 */

import { AnalyticsAPI } from '../src/analytics';
import { HttpClient } from '../src/client';
import { TemporalPattern, HealthResponse, MetricsSummary } from '../src/types';

jest.mock('../src/client');

describe('AnalyticsAPI', () => {
  let analyticsAPI: AnalyticsAPI;
  let mockClient: jest.Mocked<HttpClient>;

  beforeEach(() => {
    mockClient = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn()
    } as unknown as jest.Mocked<HttpClient>;

    analyticsAPI = new AnalyticsAPI(mockClient);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getTemporalPattern', () => {
    it('should get temporal pattern with string dates', async () => {
      const options = {
        start_time: '2025-01-01T00:00:00Z',
        end_time: '2025-01-31T23:59:59Z'
      };

      const expectedResponse: TemporalPattern = {
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        start_time: '2025-01-01T00:00:00Z',
        end_time: '2025-01-31T23:59:59Z',
        hourly_distribution: { 9: 120, 10: 145, 14: 132 },
        daily_distribution: { '2025-01-01': 45, '2025-01-02': 67 },
        peak_hours: [9, 10, 14],
        off_hours_activity_percentage: 15.5,
        weekend_activity_percentage: 8.2,
        top_domains: [
          { domain: 'api.example.com', count: 523 },
          { domain: 'app.example.com', count: 412 }
        ],
        anomalies: [
          {
            type: 'activity_spike',
            severity: 'low',
            description: 'Unusual activity spike at hour 23'
          }
        ],
        compliance_score: 87.5
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await analyticsAPI.getTemporalPattern(options);

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/audit/analytics', {
        params: {
          start_time: '2025-01-01T00:00:00Z',
          end_time: '2025-01-31T23:59:59Z'
        }
      });
      expect(result).toEqual(expectedResponse);
    });

    it('should get temporal pattern with Date objects', async () => {
      const startDate = new Date('2025-01-01T00:00:00Z');
      const endDate = new Date('2025-01-31T23:59:59Z');

      const options = {
        start_time: startDate,
        end_time: endDate
      };

      const expectedResponse: TemporalPattern = {
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        start_time: startDate.toISOString(),
        end_time: endDate.toISOString(),
        hourly_distribution: {},
        daily_distribution: {},
        peak_hours: [],
        off_hours_activity_percentage: 0,
        weekend_activity_percentage: 0,
        top_domains: [],
        anomalies: [],
        compliance_score: 100
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await analyticsAPI.getTemporalPattern(options);

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/audit/analytics', {
        params: {
          start_time: startDate.toISOString(),
          end_time: endDate.toISOString()
        }
      });
      expect(result).toEqual(expectedResponse);
    });

    it('should return temporal pattern with anomalies', async () => {
      const options = {
        start_time: '2025-01-01T00:00:00Z',
        end_time: '2025-01-31T23:59:59Z'
      };

      const expectedResponse: TemporalPattern = {
        tenant_id: '550e8400-e29b-41d4-a716-446655440001',
        start_time: '2025-01-01T00:00:00Z',
        end_time: '2025-01-31T23:59:59Z',
        hourly_distribution: {},
        daily_distribution: {},
        peak_hours: [],
        off_hours_activity_percentage: 25.5,
        weekend_activity_percentage: 35.2,
        top_domains: [],
        anomalies: [
          {
            type: 'off_hours_spike',
            severity: 'medium',
            description: 'High activity during off hours'
          },
          {
            type: 'weekend_activity',
            severity: 'high',
            description: 'Unusual weekend activity detected'
          }
        ],
        compliance_score: 65.0
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await analyticsAPI.getTemporalPattern(options);

      expect(result.anomalies).toHaveLength(2);
      expect(result.compliance_score).toBe(65.0);
    });
  });

  describe('healthCheck', () => {
    it('should get health status', async () => {
      const expectedResponse: HealthResponse = {
        status: 'healthy',
        timestamp: '2025-01-15T12:00:00Z',
        service: 'chronoguard',
        version: '1.0.0'
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await analyticsAPI.healthCheck();

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/health/');
      expect(result).toEqual(expectedResponse);
      expect(result.status).toBe('healthy');
    });
  });

  describe('readinessCheck', () => {
    it('should get readiness status with database info', async () => {
      const expectedResponse: HealthResponse = {
        status: 'ready',
        timestamp: '2025-01-15T12:00:00Z',
        service: 'chronoguard',
        version: '1.0.0',
        database: 'connected'
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await analyticsAPI.readinessCheck();

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/health/ready');
      expect(result).toEqual(expectedResponse);
      expect(result.database).toBe('connected');
    });

    it('should handle readiness check without database field', async () => {
      const expectedResponse: HealthResponse = {
        status: 'ready',
        timestamp: '2025-01-15T12:00:00Z',
        service: 'chronoguard',
        version: '1.0.0'
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await analyticsAPI.readinessCheck();

      expect(result.database).toBeUndefined();
    });
  });

  describe('getMetrics', () => {
    it('should get metrics summary', async () => {
      const expectedResponse: MetricsSummary = {
        timestamp: '2025-01-15T12:00:00Z',
        agents: {
          total: 25,
          active: 20,
          suspended: 3,
          pending: 2
        },
        policies: {
          total: 10,
          active: 8
        },
        recent_activity: {
          last_hour: 150,
          last_day: 3500
        }
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await analyticsAPI.getMetrics();

      expect(mockClient.get).toHaveBeenCalledWith('/api/v1/health/metrics');
      expect(result).toEqual(expectedResponse);
      expect(result.agents.total).toBe(25);
      expect(result.agents.active).toBe(20);
      expect(result.policies.total).toBe(10);
    });

    it('should handle metrics without recent activity', async () => {
      const expectedResponse: MetricsSummary = {
        timestamp: '2025-01-15T12:00:00Z',
        agents: {
          total: 0,
          active: 0,
          suspended: 0,
          pending: 0
        },
        policies: {
          total: 0,
          active: 0
        }
      };

      mockClient.get.mockResolvedValue(expectedResponse);

      const result = await analyticsAPI.getMetrics();

      expect(result.recent_activity).toBeUndefined();
    });
  });
});
