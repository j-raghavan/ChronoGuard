/**
 * HTTP Client test suite
 */

import axios from 'axios';
import { HttpClient } from '../src/client';
import { ConfigurationError } from '../src/errors';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('HttpClient', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    // Setup default axios.create mock
    mockedAxios.create.mockReturnValue({
      interceptors: {
        request: { use: jest.fn() },
        response: { use: jest.fn() }
      },
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn()
    } as never);
  });

  describe('Constructor', () => {
    it('should create client with valid config', () => {
      const client = new HttpClient({ apiUrl: 'http://localhost:8000' });
      expect(client).toBeInstanceOf(HttpClient);
      expect(client.getBaseUrl()).toBe('http://localhost:8000');
    });

    it('should throw ConfigurationError if apiUrl is missing', () => {
      expect(() => new HttpClient({} as never)).toThrow(ConfigurationError);
      expect(() => new HttpClient({} as never)).toThrow('apiUrl is required');
    });

    it('should throw ConfigurationError if apiUrl is invalid', () => {
      expect(() => new HttpClient({ apiUrl: 'invalid' })).toThrow(ConfigurationError);
      expect(() => new HttpClient({ apiUrl: 'invalid' })).toThrow('must start with http');
    });

    it('should accept https URLs', () => {
      const client = new HttpClient({ apiUrl: 'https://api.example.com' });
      expect(client.getBaseUrl()).toBe('https://api.example.com');
    });

    it('should set default timeout', () => {
      new HttpClient({ apiUrl: 'http://localhost:8000' });

      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({
          timeout: 30000
        })
      );
    });

    it('should use custom timeout', () => {
      new HttpClient({ apiUrl: 'http://localhost:8000', timeout: 5000 });

      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({
          timeout: 5000
        })
      );
    });

    it('should include custom headers', () => {
      const headers = { 'X-Custom': 'value' };
      new HttpClient({ apiUrl: 'http://localhost:8000', headers });

      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-Custom': 'value'
          })
        })
      );
    });
  });

  describe('Tenant and User ID', () => {
    let client: HttpClient;

    beforeEach(() => {
      client = new HttpClient({ apiUrl: 'http://localhost:8000' });
    });

    it('should set and get tenant ID', () => {
      const tenantId = '550e8400-e29b-41d4-a716-446655440001';
      client.setTenantId(tenantId);
      expect(client.getTenantId()).toBe(tenantId);
    });

    it('should set and get user ID', () => {
      const userId = '550e8400-e29b-41d4-a716-446655440002';
      client.setUserId(userId);
      expect(client.getUserId()).toBe(userId);
    });

    it('should return undefined if tenant ID not set', () => {
      expect(client.getTenantId()).toBeUndefined();
    });

    it('should return undefined if user ID not set', () => {
      expect(client.getUserId()).toBeUndefined();
    });
  });

  describe('HTTP Methods', () => {
    let client: HttpClient;
    let mockAxiosInstance: {
      get: jest.Mock;
      post: jest.Mock;
      put: jest.Mock;
      delete: jest.Mock;
      interceptors: {
        request: { use: jest.Mock };
        response: { use: jest.Mock };
      };
    };

    beforeEach(() => {
      mockAxiosInstance = {
        get: jest.fn(),
        post: jest.fn(),
        put: jest.fn(),
        delete: jest.fn(),
        interceptors: {
          request: { use: jest.fn() },
          response: { use: jest.fn() }
        }
      };

      mockedAxios.create.mockReturnValueOnce(mockAxiosInstance as never);
      client = new HttpClient({ apiUrl: 'http://localhost:8000' });
    });

    describe('GET', () => {
      it('should perform GET request', async () => {
        const responseData = { id: 1, name: 'test' };
        mockAxiosInstance.get.mockResolvedValue({ data: responseData });

        const result = await client.get('/test');

        expect(mockAxiosInstance.get).toHaveBeenCalledWith('/test', undefined);
        expect(result).toEqual(responseData);
      });

      it('should pass config to GET request', async () => {
        mockAxiosInstance.get.mockResolvedValue({ data: {} });
        const config = { params: { page: 1 } };

        await client.get('/test', config);

        expect(mockAxiosInstance.get).toHaveBeenCalledWith('/test', config);
      });
    });

    describe('POST', () => {
      it('should perform POST request', async () => {
        const requestData = { name: 'test' };
        const responseData = { id: 1, name: 'test' };
        mockAxiosInstance.post.mockResolvedValue({ data: responseData });

        const result = await client.post('/test', requestData);

        expect(mockAxiosInstance.post).toHaveBeenCalledWith('/test', requestData, undefined);
        expect(result).toEqual(responseData);
      });

      it('should pass config to POST request', async () => {
        mockAxiosInstance.post.mockResolvedValue({ data: {} });
        const config = { headers: { 'X-Custom': 'value' } };

        await client.post('/test', {}, config);

        expect(mockAxiosInstance.post).toHaveBeenCalledWith('/test', {}, config);
      });
    });

    describe('PUT', () => {
      it('should perform PUT request', async () => {
        const requestData = { name: 'updated' };
        const responseData = { id: 1, name: 'updated' };
        mockAxiosInstance.put.mockResolvedValue({ data: responseData });

        const result = await client.put('/test/1', requestData);

        expect(mockAxiosInstance.put).toHaveBeenCalledWith('/test/1', requestData, undefined);
        expect(result).toEqual(responseData);
      });
    });

    describe('DELETE', () => {
      it('should perform DELETE request', async () => {
        mockAxiosInstance.delete.mockResolvedValue({ data: null });

        const result = await client.delete('/test/1');

        expect(mockAxiosInstance.delete).toHaveBeenCalledWith('/test/1', undefined);
        expect(result).toBeNull();
      });
    });
  });

  // Error handling is tested through the error classes tests in errors.test.ts
});
