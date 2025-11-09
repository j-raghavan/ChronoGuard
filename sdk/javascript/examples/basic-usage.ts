/**
 * Basic usage examples for ChronoGuard SDK
 *
 * This file demonstrates common SDK operations.
 */

import { ChronoGuard } from '../src/index';

async function main(): Promise<void> {
  // Initialize the SDK
  const client = new ChronoGuard({
    apiUrl: 'http://localhost:8000',
    tenantId: '550e8400-e29b-41d4-a716-446655440001',
    userId: '550e8400-e29b-41d4-a716-446655440002',
    debug: true
  });

  try {
    // Create an agent
    console.log('\n=== Creating Agent ===');
    const agent = await client.agents.create({
      name: 'qa-agent-prod-01',
      certificate_pem: '-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----',
      metadata: { environment: 'production', team: 'qa' }
    });
    console.log('Agent created:', agent.agent_id);

    // List all agents
    console.log('\n=== Listing Agents ===');
    const agentsList = await client.agents.list({ page: 1, page_size: 10 });
    console.log(`Total agents: ${agentsList.total_count}`);

    // Create a policy
    console.log('\n=== Creating Policy ===');
    const policy = await client.policies.create({
      name: 'production-qa-policy',
      description: 'Access policy for production QA agents',
      priority: 500,
      allowed_domains: ['example.com', 'test.example.com'],
      blocked_domains: [],
      metadata: { environment: 'production' }
    });
    console.log('Policy created:', policy.policy_id);

    // Query audit logs
    console.log('\n=== Querying Audit Logs ===');
    const auditLogs = await client.audit.query({
      tenant_id: client.getTenantId(),
      start_time: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
      end_time: new Date().toISOString(),
      page: 1,
      page_size: 50
    });
    console.log(`Found ${auditLogs.total_count} audit entries`);

    // Get temporal analytics
    console.log('\n=== Getting Temporal Analytics ===');
    const analytics = await client.analytics.getTemporalPattern({
      start_time: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      end_time: new Date().toISOString()
    });
    console.log(`Compliance Score: ${analytics.compliance_score}`);
    console.log(`Peak Hours: ${analytics.peak_hours.join(', ')}`);

    // Health check
    console.log('\n=== Health Check ===');
    const health = await client.analytics.healthCheck();
    console.log(`Service: ${health.service} v${health.version} - ${health.status}`);

  } catch (error) {
    console.error('Error:', error);
  }
}

// Run example
if (require.main === module) {
  main().catch(console.error);
}

export { main };
