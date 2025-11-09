/**
 * ChronoGuard Agent Management API
 *
 * Provides methods for managing agents (CRUD operations).
 */

import { HttpClient } from './client';
import {
  Agent,
  AgentListResponse,
  CreateAgentRequest,
  UpdateAgentRequest,
  AgentListOptions,
  UUID
} from './types';

/**
 * Agent management API client
 */
export class AgentAPI {
  private readonly client: HttpClient;

  constructor(client: HttpClient) {
    this.client = client;
  }

  /**
   * Create a new agent
   *
   * @param request - Agent creation request
   * @returns Created agent
   *
   * @throws {ValidationError} If request validation fails
   * @throws {ConflictError} If agent name already exists
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * const agent = await client.agents.create({
   *   name: 'qa-agent-prod-01',
   *   certificate_pem: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
   *   metadata: { environment: 'production' }
   * });
   * console.log(`Created agent: ${agent.agent_id}`);
   * ```
   */
  async create(request: CreateAgentRequest): Promise<Agent> {
    return this.client.post<Agent, CreateAgentRequest>('/api/v1/agents/', request);
  }

  /**
   * Get an agent by ID
   *
   * @param agentId - Agent identifier
   * @returns Agent details
   *
   * @throws {NotFoundError} If agent is not found
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * const agent = await client.agents.get('550e8400-e29b-41d4-a716-446655440000');
   * console.log(`Agent status: ${agent.status}`);
   * ```
   */
  async get(agentId: UUID): Promise<Agent> {
    return this.client.get<Agent>(`/api/v1/agents/${agentId}`);
  }

  /**
   * List all agents for the current tenant
   *
   * @param options - Pagination and filtering options
   * @returns Paginated list of agents
   *
   * @throws {ValidationError} If pagination parameters are invalid
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * const response = await client.agents.list({
   *   page: 1,
   *   page_size: 50,
   *   status_filter: 'active'
   * });
   * console.log(`Total agents: ${response.total_count}`);
   * response.agents.forEach(agent => console.log(agent.name));
   * ```
   */
  async list(options: AgentListOptions = {}): Promise<AgentListResponse> {
    const params: Record<string, string | number> = {};

    if (options.page !== undefined) {
      params.page = options.page;
    }
    if (options.page_size !== undefined) {
      params.page_size = options.page_size;
    }
    if (options.status_filter !== undefined) {
      params.status_filter = options.status_filter;
    }

    return this.client.get<AgentListResponse>('/api/v1/agents/', { params });
  }

  /**
   * Update an existing agent
   *
   * @param agentId - Agent identifier
   * @param request - Update request (all fields optional)
   * @returns Updated agent
   *
   * @throws {NotFoundError} If agent is not found
   * @throws {ValidationError} If request validation fails
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * const updatedAgent = await client.agents.update(
   *   '550e8400-e29b-41d4-a716-446655440000',
   *   { name: 'qa-agent-prod-02' }
   * );
   * console.log(`Updated agent: ${updatedAgent.name}`);
   * ```
   */
  async update(agentId: UUID, request: UpdateAgentRequest): Promise<Agent> {
    return this.client.put<Agent, UpdateAgentRequest>(`/api/v1/agents/${agentId}`, request);
  }
}
