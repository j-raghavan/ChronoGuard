/**
 * Error classes test suite
 */

import {
  ChronoGuardError,
  NetworkError,
  TimeoutError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ValidationError,
  ConflictError,
  RateLimitError,
  ServerError,
  ConfigurationError,
  createErrorFromResponse
} from '../src/errors';

describe('Error Classes', () => {
  describe('ChronoGuardError', () => {
    it('should create error with message', () => {
      const error = new ChronoGuardError('Test error');
      expect(error.message).toBe('Test error');
      expect(error.name).toBe('ChronoGuardError');
      expect(error.statusCode).toBeUndefined();
      expect(error.details).toBeUndefined();
    });

    it('should create error with status code and details', () => {
      const details = { field: 'test' };
      const error = new ChronoGuardError('Test error', 400, details);
      expect(error.statusCode).toBe(400);
      expect(error.details).toEqual(details);
    });

    it('should be instance of Error', () => {
      const error = new ChronoGuardError('Test');
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(ChronoGuardError);
    });
  });

  describe('NetworkError', () => {
    it('should create network error', () => {
      const error = new NetworkError('Connection failed');
      expect(error.message).toBe('Connection failed');
      expect(error.name).toBe('NetworkError');
      expect(error).toBeInstanceOf(ChronoGuardError);
    });
  });

  describe('TimeoutError', () => {
    it('should create timeout error with default message', () => {
      const error = new TimeoutError();
      expect(error.message).toBe('Request timeout');
      expect(error.name).toBe('TimeoutError');
      expect(error.statusCode).toBe(408);
    });

    it('should create timeout error with custom message', () => {
      const error = new TimeoutError('Custom timeout');
      expect(error.message).toBe('Custom timeout');
    });
  });

  describe('AuthenticationError', () => {
    it('should create auth error with default message', () => {
      const error = new AuthenticationError();
      expect(error.message).toBe('Authentication failed');
      expect(error.statusCode).toBe(401);
    });

    it('should create auth error with custom message', () => {
      const error = new AuthenticationError('Invalid token');
      expect(error.message).toBe('Invalid token');
    });
  });

  describe('AuthorizationError', () => {
    it('should create authz error', () => {
      const error = new AuthorizationError('Access denied');
      expect(error.message).toBe('Access denied');
      expect(error.statusCode).toBe(403);
    });
  });

  describe('NotFoundError', () => {
    it('should create not found error', () => {
      const error = new NotFoundError('Resource not found');
      expect(error.message).toBe('Resource not found');
      expect(error.statusCode).toBe(404);
    });
  });

  describe('ValidationError', () => {
    it('should create validation error', () => {
      const error = new ValidationError('Invalid input');
      expect(error.message).toBe('Invalid input');
      expect(error.statusCode).toBe(400);
    });
  });

  describe('ConflictError', () => {
    it('should create conflict error', () => {
      const error = new ConflictError('Resource exists');
      expect(error.message).toBe('Resource exists');
      expect(error.statusCode).toBe(409);
    });
  });

  describe('RateLimitError', () => {
    it('should create rate limit error with default message', () => {
      const error = new RateLimitError();
      expect(error.message).toBe('Rate limit exceeded');
      expect(error.statusCode).toBe(429);
      expect(error.retryAfter).toBeUndefined();
    });

    it('should create rate limit error with retry after', () => {
      const error = new RateLimitError('Too many requests', 60);
      expect(error.retryAfter).toBe(60);
    });
  });

  describe('ServerError', () => {
    it('should create server error with default values', () => {
      const error = new ServerError();
      expect(error.message).toBe('Internal server error');
      expect(error.statusCode).toBe(500);
    });

    it('should create server error with custom status', () => {
      const error = new ServerError('Bad gateway', 502);
      expect(error.message).toBe('Bad gateway');
      expect(error.statusCode).toBe(502);
    });
  });

  describe('ConfigurationError', () => {
    it('should create configuration error', () => {
      const error = new ConfigurationError('Invalid config');
      expect(error.message).toBe('Invalid config');
      expect(error.name).toBe('ConfigurationError');
    });
  });

  describe('createErrorFromResponse', () => {
    it('should create ValidationError for 400', () => {
      const error = createErrorFromResponse(400, 'Bad request');
      expect(error).toBeInstanceOf(ValidationError);
      expect(error.statusCode).toBe(400);
    });

    it('should create AuthenticationError for 401', () => {
      const error = createErrorFromResponse(401, 'Unauthorized');
      expect(error).toBeInstanceOf(AuthenticationError);
    });

    it('should create AuthorizationError for 403', () => {
      const error = createErrorFromResponse(403, 'Forbidden');
      expect(error).toBeInstanceOf(AuthorizationError);
    });

    it('should create NotFoundError for 404', () => {
      const error = createErrorFromResponse(404, 'Not found');
      expect(error).toBeInstanceOf(NotFoundError);
    });

    it('should create TimeoutError for 408', () => {
      const error = createErrorFromResponse(408, 'Timeout');
      expect(error).toBeInstanceOf(TimeoutError);
    });

    it('should create ConflictError for 409', () => {
      const error = createErrorFromResponse(409, 'Conflict');
      expect(error).toBeInstanceOf(ConflictError);
    });

    it('should create RateLimitError for 429', () => {
      const error = createErrorFromResponse(429, 'Rate limited');
      expect(error).toBeInstanceOf(RateLimitError);
    });

    it('should create ServerError for 500', () => {
      const error = createErrorFromResponse(500, 'Server error');
      expect(error).toBeInstanceOf(ServerError);
      expect(error.statusCode).toBe(500);
    });

    it('should create ServerError for 502', () => {
      const error = createErrorFromResponse(502, 'Bad gateway');
      expect(error).toBeInstanceOf(ServerError);
      expect(error.statusCode).toBe(502);
    });

    it('should create generic ChronoGuardError for unknown codes', () => {
      const error = createErrorFromResponse(418, "I'm a teapot");
      expect(error).toBeInstanceOf(ChronoGuardError);
      expect(error).not.toBeInstanceOf(ValidationError);
      expect(error.statusCode).toBe(418);
    });

    it('should include details in error', () => {
      const details = { field: 'name', error: 'required' };
      const error = createErrorFromResponse(400, 'Validation failed', details);
      expect(error.details).toEqual(details);
    });
  });
});
