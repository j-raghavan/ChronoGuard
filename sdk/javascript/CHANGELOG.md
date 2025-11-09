# Changelog

All notable changes to the ChronoGuard JavaScript/TypeScript SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-08

### Added
- Initial release of ChronoGuard JavaScript/TypeScript SDK
- Agent Management API
  - Create, read, update agents
  - List agents with pagination and filtering
  - Full TypeScript type definitions
- Policy Management API
  - Create, read, update, delete policies
  - List policies with pagination and filtering
  - Support for allowed/blocked domains
- Audit Log API
  - Query audit entries with flexible filtering
  - Export audit logs to CSV and JSON formats
  - Pagination support
- Temporal Analytics API
  - Get temporal pattern analysis
  - Health and readiness checks
  - System metrics summary
- Comprehensive error handling
  - Custom error classes for different HTTP status codes
  - NetworkError, TimeoutError, ValidationError, etc.
  - Detailed error messages and context
- TypeScript support
  - Complete type definitions (500+ lines)
  - Strict type checking
  - IntelliSense support in IDEs
- Testing
  - 100% coverage for all API modules
  - 97.22% branch coverage
  - 91 passing tests
  - Jest configuration with coverage thresholds
- Documentation
  - Comprehensive README with examples
  - API reference documentation
  - Usage examples for all features
  - TypeScript code examples

### Technical Details
- Built with TypeScript 5.3
- Uses Axios for HTTP requests
- Promise-based async/await API
- Configurable timeout and headers
- Debug logging support
- Multi-tenant support via headers

## [Unreleased]

### Planned
- WebSocket support for real-time updates
- Batch operations for agents and policies
- Advanced query builders
- Response caching
- Retry logic with exponential backoff
- Request interceptors and middleware
