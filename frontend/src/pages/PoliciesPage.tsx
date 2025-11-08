import { usePolicies } from '@/hooks/useApi';
import { FileText } from 'lucide-react';
import { format } from 'date-fns';

export function PoliciesPage() {
  const { data, isLoading, error } = usePolicies();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-muted-foreground">Loading policies...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-destructive">Error loading policies</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Policies</h2>
          <p className="text-muted-foreground">
            Manage access policies and rules
          </p>
        </div>
        <button className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90">
          Create Policy
        </button>
      </div>

      <div className="grid gap-4">
        {data?.policies.map((policy) => (
          <div
            key={policy.policy_id}
            className="rounded-lg border border-border bg-card p-6 hover:bg-muted/50 transition-colors"
          >
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-4">
                <FileText className="h-6 w-6 text-muted-foreground mt-1" />
                <div>
                  <h3 className="text-lg font-semibold">{policy.name}</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    {policy.description}
                  </p>
                  <div className="flex items-center gap-4 mt-3">
                    <span
                      className={`px-2 py-1 text-xs font-medium rounded-full ${
                        policy.is_active
                          ? 'bg-green-100 text-green-800'
                          : 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {policy.is_active ? 'Active' : 'Inactive'}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      Priority: {policy.priority}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {policy.rules.length} rules
                    </span>
                    <span className="text-xs text-muted-foreground">
                      Default: {policy.default_action}
                    </span>
                  </div>
                </div>
              </div>
              <div className="text-right">
                <div className="text-sm text-muted-foreground">
                  Created {format(new Date(policy.created_at), 'MMM dd, yyyy')}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Version {policy.version}
                </div>
              </div>
            </div>

            {policy.allowed_domains.length > 0 && (
              <div className="mt-4 pt-4 border-t border-border">
                <div className="text-sm font-medium mb-2">Allowed Domains</div>
                <div className="flex flex-wrap gap-2">
                  {policy.allowed_domains.slice(0, 5).map((domain, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-1 bg-green-50 text-green-700 text-xs rounded"
                    >
                      {domain}
                    </span>
                  ))}
                  {policy.allowed_domains.length > 5 && (
                    <span className="px-2 py-1 bg-muted text-muted-foreground text-xs rounded">
                      +{policy.allowed_domains.length - 5} more
                    </span>
                  )}
                </div>
              </div>
            )}

            {policy.blocked_domains.length > 0 && (
              <div className="mt-3">
                <div className="text-sm font-medium mb-2">Blocked Domains</div>
                <div className="flex flex-wrap gap-2">
                  {policy.blocked_domains.slice(0, 5).map((domain, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-1 bg-red-50 text-red-700 text-xs rounded"
                    >
                      {domain}
                    </span>
                  ))}
                  {policy.blocked_domains.length > 5 && (
                    <span className="px-2 py-1 bg-muted text-muted-foreground text-xs rounded">
                      +{policy.blocked_domains.length - 5} more
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
