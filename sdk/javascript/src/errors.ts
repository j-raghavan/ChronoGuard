/**
 * ChronoGuard SDK Error Classes
 *
 * Custom error classes for better error handling and debugging.
 */

/**
 * Base error class for all ChronoGuard SDK errors
 */
export class ChronoGuardError extends Error {
  /**
   * HTTP status code if applicable
   */
  public readonly statusCode?: number;

  /**
   * Additional error details
   */
  public readonly details?: unknown;

  constructor(message: string, statusCode?: number, details?: unknown) {
    super(message);
    this.name = 'ChronoGuardError';
    this.statusCode = statusCode;
    this.details = details;
    Object.setPrototypeOf(this, ChronoGuardError.prototype);
  }
}

/**
 * Error thrown when API request fails due to network issues
 */
export class NetworkError extends ChronoGuardError {
  constructor(message: string, details?: unknown) {
    super(message, undefined, details);
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

/**
 * Error thrown when API request times out
 */
export class TimeoutError extends ChronoGuardError {
  constructor(message = 'Request timeout', details?: unknown) {
    super(message, 408, details);
    this.name = 'TimeoutError';
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

/**
 * Error thrown when authentication fails (401)
 */
export class AuthenticationError extends ChronoGuardError {
  constructor(message = 'Authentication failed', details?: unknown) {
    super(message, 401, details);
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

/**
 * Error thrown when authorization fails (403)
 */
export class AuthorizationError extends ChronoGuardError {
  constructor(message = 'Access forbidden', details?: unknown) {
    super(message, 403, details);
    this.name = 'AuthorizationError';
    Object.setPrototypeOf(this, AuthorizationError.prototype);
  }
}

/**
 * Error thrown when resource is not found (404)
 */
export class NotFoundError extends ChronoGuardError {
  constructor(message: string, details?: unknown) {
    super(message, 404, details);
    this.name = 'NotFoundError';
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

/**
 * Error thrown when request validation fails (400)
 */
export class ValidationError extends ChronoGuardError {
  constructor(message: string, details?: unknown) {
    super(message, 400, details);
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

/**
 * Error thrown when resource already exists (409)
 */
export class ConflictError extends ChronoGuardError {
  constructor(message: string, details?: unknown) {
    super(message, 409, details);
    this.name = 'ConflictError';
    Object.setPrototypeOf(this, ConflictError.prototype);
  }
}

/**
 * Error thrown when rate limit is exceeded (429)
 */
export class RateLimitError extends ChronoGuardError {
  /**
   * Time in seconds until rate limit resets
   */
  public readonly retryAfter?: number;

  constructor(message = 'Rate limit exceeded', retryAfter?: number, details?: unknown) {
    super(message, 429, details);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

/**
 * Error thrown when server returns 5xx error
 */
export class ServerError extends ChronoGuardError {
  constructor(message = 'Internal server error', statusCode = 500, details?: unknown) {
    super(message, statusCode, details);
    this.name = 'ServerError';
    Object.setPrototypeOf(this, ServerError.prototype);
  }
}

/**
 * Error thrown when configuration is invalid
 */
export class ConfigurationError extends ChronoGuardError {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

/**
 * Map HTTP status codes to appropriate error classes
 */
export function createErrorFromResponse(
  statusCode: number,
  message: string,
  details?: unknown
): ChronoGuardError {
  switch (statusCode) {
    case 400:
      return new ValidationError(message, details);
    case 401:
      return new AuthenticationError(message, details);
    case 403:
      return new AuthorizationError(message, details);
    case 404:
      return new NotFoundError(message, details);
    case 409:
      return new ConflictError(message, details);
    case 429:
      return new RateLimitError(message, undefined, details);
    case 408:
      return new TimeoutError(message, details);
    default:
      if (statusCode >= 500) {
        return new ServerError(message, statusCode, details);
      }
      return new ChronoGuardError(message, statusCode, details);
  }
}
