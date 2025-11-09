# ChronoGuard JavaScript/TypeScript SDK

Official TypeScript/JavaScript SDK for ChronoGuard - Temporal Access Control System

[![npm version](https://badge.fury.io/js/%40chronoguard%2Fsdk.svg)](https://www.npmjs.com/package/@chronoguard/sdk)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Full TypeScript Support** - Complete type definitions for all API operations
- **Promise-Based API** - Modern async/await syntax
- **Comprehensive Error Handling** - Detailed error classes for different failure scenarios
- **Agent Management** - CRUD operations for managing agents
- **Policy Management** - Create, update, and delete access policies
- **Audit Log Querying** - Query and export audit logs with flexible filtering
- **Temporal Analytics** - Analyze access patterns and detect anomalies
- **95%+ Test Coverage** - Thoroughly tested with Jest

## Installation

```bash
npm install @chronoguard/sdk
```

Or using yarn:

```bash
yarn add @chronoguard/sdk
```

## Quick Start

```typescript
import { ChronoGuard } from '@chronoguard/sdk';

// Initialize the SDK
const client = new ChronoGuard({
  apiUrl: 'http://localhost:8000',
  tenantId: '550e8400-e29b-41d4-a716-446655440001',
  userId: '550e8400-e29b-41d4-a716-446655440002'
});

// Create an agent
const agent = await client.agents.create({
  name: 'qa-agent-prod-01',
  certificate_pem: certificatePem,
  metadata: { environment: 'production' }
});

console.log(`Created agent: ${agent.agent_id}`);
```

## Configuration

The SDK accepts the following configuration options:

```typescript
interface ChronoGuardConfig {
  apiUrl: string;           // Base URL for the ChronoGuard API (required)
  tenantId?: string;        // Tenant ID for multi-tenant requests
  userId?: string;          // User ID for operations requiring user context
  timeout?: number;         // Request timeout in milliseconds (default: 30000)
  headers?: Record<string, string>; // Custom headers for all requests
  debug?: boolean;          // Enable debug logging (default: false)
}
```

## Usage Examples

### Agent Management

#### Create an Agent

```typescript
const agent = await client.agents.create({
  name: 'qa-agent-prod-01',
  certificate_pem: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
  metadata: {
    environment: 'production',
    team: 'qa'
  }
});
```

#### Get an Agent

```typescript
const agent = await client.agents.get('550e8400-e29b-41d4-a716-446655440000');
console.log(`Agent status: ${agent.status}`);
```

#### List Agents

```typescript
const response = await client.agents.list({
  page: 1,
  page_size: 50,
  status_filter: 'active'
});

console.log(`Total agents: ${response.total_count}`);
response.agents.forEach(agent => {
  console.log(`${agent.name} - ${agent.status}`);
});
```

#### Update an Agent

```typescript
const updatedAgent = await client.agents.update(
  '550e8400-e29b-41d4-a716-446655440000',
  {
    name: 'qa-agent-prod-02',
    metadata: { environment: 'staging' }
  }
);
```

### Policy Management

#### Create a Policy

```typescript
const policy = await client.policies.create({
  name: 'production-qa-policy',
  description: 'Access policy for production QA agents',
  priority: 500,
  allowed_domains: ['example.com', 'test.example.com'],
  blocked_domains: ['malicious.com'],
  metadata: {
    environment: 'production',
    team: 'qa'
  }
});
```

#### Get a Policy

```typescript
const policy = await client.policies.get('550e8400-e29b-41d4-a716-446655440000');
console.log(`Policy: ${policy.name} (${policy.status})`);
```

#### List Policies

```typescript
const response = await client.policies.list({
  page: 1,
  page_size: 50,
  status_filter: 'active'
});

console.log(`Total policies: ${response.total_count}`);
```

#### Update a Policy

```typescript
const updatedPolicy = await client.policies.update(
  '550e8400-e29b-41d4-a716-446655440000',
  {
    name: 'updated-policy-name',
    description: 'Updated description',
    priority: 600,
    allowed_domains: ['newdomain.com']
  }
);
```

#### Delete a Policy

```typescript
await client.policies.delete('550e8400-e29b-41d4-a716-446655440000');
console.log('Policy deleted successfully');
```

### Audit Log Querying

#### Query Audit Logs

```typescript
const response = await client.audit.query({
  tenant_id: '550e8400-e29b-41d4-a716-446655440001',
  agent_id: '550e8400-e29b-41d4-a716-446655440002',
  decision: 'allow',
  start_time: '2025-01-01T00:00:00Z',
  end_time: '2025-01-31T23:59:59Z',
  page: 1,
  page_size: 50
});

console.log(`Total entries: ${response.total_count}`);
response.entries.forEach(entry => {
  console.log(`${entry.timestamp}: ${entry.decision} - ${entry.domain}`);
});
```

#### Export Audit Logs to CSV

```typescript
const csvData = await client.audit.export({
  tenant_id: '550e8400-e29b-41d4-a716-446655440001',
  start_time: '2025-01-01T00:00:00Z',
  end_time: '2025-01-31T23:59:59Z',
  format: 'csv'
});

// Save to file
import { writeFileSync } from 'fs';
writeFileSync('audit_export.csv', csvData);
```

#### Export Audit Logs to JSON

```typescript
const jsonData = await client.audit.export({
  tenant_id: '550e8400-e29b-41d4-a716-446655440001',
  start_time: '2025-01-01T00:00:00Z',
  end_time: '2025-01-31T23:59:59Z',
  format: 'json',
  pretty_json: true
});

const entries = JSON.parse(jsonData);
console.log(`Exported ${entries.length} entries`);
```

### Temporal Analytics

#### Get Temporal Pattern Analysis

```typescript
const pattern = await client.analytics.getTemporalPattern({
  start_time: '2025-01-01T00:00:00Z',
  end_time: '2025-01-31T23:59:59Z'
});

console.log(`Compliance Score: ${pattern.compliance_score}`);
console.log(`Peak Hours: ${pattern.peak_hours.join(', ')}`);
console.log(`Off-hours Activity: ${pattern.off_hours_activity_percentage}%`);
console.log(`Weekend Activity: ${pattern.weekend_activity_percentage}%`);

// Analyze hourly distribution
Object.entries(pattern.hourly_distribution).forEach(([hour, count]) => {
  console.log(`Hour ${hour}: ${count} requests`);
});

// Check for anomalies
pattern.anomalies.forEach(anomaly => {
  console.log(`${anomaly.severity}: ${anomaly.description}`);
});

// Top domains
pattern.top_domains.forEach(({ domain, count }) => {
  console.log(`${domain}: ${count} requests`);
});
```

#### Using Date Objects

```typescript
const pattern = await client.analytics.getTemporalPattern({
  start_time: new Date('2025-01-01'),
  end_time: new Date('2025-01-31')
});
```

### Health and Metrics

#### Health Check

```typescript
const health = await client.analytics.healthCheck();
console.log(`Service: ${health.service} v${health.version}`);
console.log(`Status: ${health.status}`);
```

#### Readiness Check

```typescript
try {
  const ready = await client.analytics.readinessCheck();
  console.log(`Database: ${ready.database}`);
} catch (error) {
  console.error('Service not ready:', error.message);
}
```

#### Get Metrics

```typescript
const metrics = await client.analytics.getMetrics();

console.log(`Total Agents: ${metrics.agents.total}`);
console.log(`Active Agents: ${metrics.agents.active}`);
console.log(`Suspended Agents: ${metrics.agents.suspended}`);
console.log(`Pending Agents: ${metrics.agents.pending}`);

console.log(`Total Policies: ${metrics.policies.total}`);
console.log(`Active Policies: ${metrics.policies.active}`);
```

## Error Handling

The SDK provides detailed error classes for different failure scenarios:

```typescript
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
  ConfigurationError
} from '@chronoguard/sdk';

try {
  const agent = await client.agents.get('non-existent-id');
} catch (error) {
  if (error instanceof NotFoundError) {
    console.error('Agent not found:', error.message);
  } else if (error instanceof ValidationError) {
    console.error('Invalid request:', error.message);
  } else if (error instanceof NetworkError) {
    console.error('Network error:', error.message);
  } else if (error instanceof RateLimitError) {
    console.error('Rate limit exceeded, retry after:', error.retryAfter);
  } else {
    console.error('Unexpected error:', error);
  }
}
```

### Error Properties

All errors extend `ChronoGuardError` and include:

- `message`: Error message
- `statusCode`: HTTP status code (if applicable)
- `details`: Additional error details from the API

## Advanced Usage

### Dynamic Tenant/User ID

```typescript
const client = new ChronoGuard({ apiUrl: 'http://localhost:8000' });

// Set tenant ID dynamically
client.setTenantId('550e8400-e29b-41d4-a716-446655440001');

// Set user ID dynamically
client.setUserId('550e8400-e29b-41d4-a716-446655440002');

// Get current IDs
console.log(client.getTenantId());
console.log(client.getUserId());
```

### Custom Headers

```typescript
const client = new ChronoGuard({
  apiUrl: 'http://localhost:8000',
  headers: {
    'X-Custom-Header': 'value',
    'X-Request-ID': 'unique-id'
  }
});
```

### Debug Mode

```typescript
const client = new ChronoGuard({
  apiUrl: 'http://localhost:8000',
  debug: true  // Enables console logging of requests/responses
});
```

### Custom Timeout

```typescript
const client = new ChronoGuard({
  apiUrl: 'http://localhost:8000',
  timeout: 5000  // 5 seconds
});
```

## TypeScript Support

The SDK is written in TypeScript and provides complete type definitions:

```typescript
import {
  Agent,
  Policy,
  AuditEntry,
  TemporalPattern,
  AgentStatus,
  PolicyStatus,
  AccessDecision,
  ChronoGuardConfig
} from '@chronoguard/sdk';

// All types are fully typed
const config: ChronoGuardConfig = {
  apiUrl: 'http://localhost:8000'
};

const client = new ChronoGuard(config);

// Return types are automatically inferred
const agent: Agent = await client.agents.get('agent-id');
const policies: Policy[] = (await client.policies.list()).policies;
```

## API Reference

### ChronoGuard

Main SDK client class.

#### Constructor

```typescript
constructor(config: ChronoGuardConfig)
```

#### Properties

- `agents: AgentAPI` - Agent management API
- `policies: PolicyAPI` - Policy management API
- `audit: AuditAPI` - Audit log API
- `analytics: AnalyticsAPI` - Analytics and monitoring API

#### Methods

- `setTenantId(tenantId: string): void` - Update tenant ID
- `setUserId(userId: string): void` - Update user ID
- `getTenantId(): string | undefined` - Get current tenant ID
- `getUserId(): string | undefined` - Get current user ID
- `getBaseUrl(): string` - Get API base URL

### AgentAPI

Agent management operations.

- `create(request: CreateAgentRequest): Promise<Agent>`
- `get(agentId: string): Promise<Agent>`
- `list(options?: AgentListOptions): Promise<AgentListResponse>`
- `update(agentId: string, request: UpdateAgentRequest): Promise<Agent>`

### PolicyAPI

Policy management operations.

- `create(request: CreatePolicyRequest): Promise<Policy>`
- `get(policyId: string): Promise<Policy>`
- `list(options?: PolicyListOptions): Promise<PolicyListResponse>`
- `update(policyId: string, request: UpdatePolicyRequest): Promise<Policy>`
- `delete(policyId: string): Promise<void>`

### AuditAPI

Audit log operations.

- `query(request: AuditQueryRequest): Promise<AuditListResponse>`
- `export(request: AuditExportRequest): Promise<string>`

### AnalyticsAPI

Analytics and monitoring operations.

- `getTemporalPattern(options: TemporalAnalyticsOptions): Promise<TemporalPattern>`
- `healthCheck(): Promise<HealthResponse>`
- `readinessCheck(): Promise<HealthResponse>`
- `getMetrics(): Promise<MetricsSummary>`

## Development

### Building

```bash
npm run build
```

### Testing

```bash
npm test
```

### Test Coverage

```bash
npm run test -- --coverage
```

The SDK maintains 95%+ test coverage.

### Linting

```bash
npm run lint
```

### Formatting

```bash
npm run format
```

## Contributing

Contributions are welcome! Please see our [Contributing Guide](../../CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](../../LICENSE) file for details.

## Support

- GitHub Issues: https://github.com/chronoguard/chronoguard/issues
- Documentation: https://chronoguard.dev/docs
- Email: support@chronoguard.dev

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for version history.

## Acknowledgments

Built with:
- [TypeScript](https://www.typescriptlang.org/)
- [Axios](https://axios-http.com/)
- [Jest](https://jestjs.io/)
