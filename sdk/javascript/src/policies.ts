/**
 * ChronoGuard Policy Management API
 *
 * Provides methods for managing policies (CRUD operations).
 */

import { HttpClient } from './client';
import {
  Policy,
  PolicyListResponse,
  CreatePolicyRequest,
  UpdatePolicyRequest,
  PolicyListOptions,
  UUID
} from './types';

/**
 * Policy management API client
 */
export class PolicyAPI {
  private readonly client: HttpClient;

  constructor(client: HttpClient) {
    this.client = client;
  }

  /**
   * Create a new policy
   *
   * @param request - Policy creation request
   * @returns Created policy
   *
   * @throws {ValidationError} If request validation fails
   * @throws {ConflictError} If policy name already exists
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * const policy = await client.policies.create({
   *   name: 'production-qa-policy',
   *   description: 'Access policy for production QA agents',
   *   priority: 500,
   *   allowed_domains: ['example.com', 'test.example.com'],
   *   blocked_domains: [],
   *   metadata: { environment: 'production' }
   * });
   * console.log(`Created policy: ${policy.policy_id}`);
   * ```
   */
  async create(request: CreatePolicyRequest): Promise<Policy> {
    return this.client.post<Policy, CreatePolicyRequest>('/api/v1/policies/', request);
  }

  /**
   * Get a policy by ID
   *
   * @param policyId - Policy identifier
   * @returns Policy details
   *
   * @throws {NotFoundError} If policy is not found
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * const policy = await client.policies.get('550e8400-e29b-41d4-a716-446655440000');
   * console.log(`Policy status: ${policy.status}`);
   * ```
   */
  async get(policyId: UUID): Promise<Policy> {
    return this.client.get<Policy>(`/api/v1/policies/${policyId}`);
  }

  /**
   * List all policies for the current tenant
   *
   * @param options - Pagination and filtering options
   * @returns Paginated list of policies
   *
   * @throws {ValidationError} If pagination parameters are invalid
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * const response = await client.policies.list({
   *   page: 1,
   *   page_size: 50,
   *   status_filter: 'active'
   * });
   * console.log(`Total policies: ${response.total_count}`);
   * response.policies.forEach(policy => console.log(policy.name));
   * ```
   */
  async list(options: PolicyListOptions = {}): Promise<PolicyListResponse> {
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

    return this.client.get<PolicyListResponse>('/api/v1/policies/', { params });
  }

  /**
   * Update an existing policy
   *
   * @param policyId - Policy identifier
   * @param request - Update request (all fields optional)
   * @returns Updated policy
   *
   * @throws {NotFoundError} If policy is not found
   * @throws {ValidationError} If request validation fails
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * const updatedPolicy = await client.policies.update(
   *   '550e8400-e29b-41d4-a716-446655440000',
   *   {
   *     name: 'updated-policy-name',
   *     description: 'Updated description',
   *     priority: 600
   *   }
   * );
   * console.log(`Updated policy: ${updatedPolicy.name}`);
   * ```
   */
  async update(policyId: UUID, request: UpdatePolicyRequest): Promise<Policy> {
    return this.client.put<Policy, UpdatePolicyRequest>(`/api/v1/policies/${policyId}`, request);
  }

  /**
   * Delete a policy
   *
   * @param policyId - Policy identifier
   *
   * @throws {NotFoundError} If policy is not found
   * @throws {ChronoGuardError} For other API errors
   *
   * @example
   * ```typescript
   * await client.policies.delete('550e8400-e29b-41d4-a716-446655440000');
   * console.log('Policy deleted successfully');
   * ```
   */
  async delete(policyId: UUID): Promise<void> {
    await this.client.delete<void>(`/api/v1/policies/${policyId}`);
  }
}
