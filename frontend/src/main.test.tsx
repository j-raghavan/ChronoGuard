import { describe, it, expect } from 'vitest';

describe('main.tsx', () => {
  it('should set default tenantId in localStorage', () => {
    const tenantId = localStorage.getItem('tenantId');
    expect(tenantId).toBe('550e8400-e29b-41d4-a716-446655440000');
  });

  it('should have tenantId as valid UUID', () => {
    const tenantId = localStorage.getItem('tenantId');
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    expect(tenantId).toMatch(uuidRegex);
  });
});
