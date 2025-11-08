import { useState } from 'react';
import { useAuditQuery } from '@/hooks/useApi';
import { format, subDays } from 'date-fns';
import { Search, Download, Filter, CheckCircle, XCircle } from 'lucide-react';
import { auditApi } from '@/services/api';

export function AuditPage() {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({
    decision: '',
    domain: '',
    startTime: subDays(new Date(), 7).toISOString(),
    endTime: new Date().toISOString(),
  });
  const [searchDomain, setSearchDomain] = useState('');

  // Get tenant ID from localStorage
  const tenantId = localStorage.getItem('tenantId') || '';

  // Query audit entries with filters
  const { data, isLoading, error, refetch } = useAuditQuery({
    tenant_id: tenantId,
    domain: filters.domain || undefined,
    decision: filters.decision || undefined,
    start_time: filters.startTime,
    end_time: filters.endTime,
    page,
    page_size: 50,
  });

  const handleSearch = () => {
    setFilters({ ...filters, domain: searchDomain });
    setPage(1);
    refetch();
  };

  const handleFilterChange = (key: string, value: string) => {
    setFilters({ ...filters, [key]: value });
    setPage(1);
  };

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      const response = await auditApi.export(format, filters.startTime, filters.endTime);
      const blob = new Blob([response.data], {
        type: format === 'csv' ? 'text/csv' : 'application/json',
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `audit_export_${format}_${Date.now()}.${format}`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export failed:', error);
    }
  };

  if (error) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-destructive">Error loading audit logs: {error.message}</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Audit Log</h2>
          <p className="text-muted-foreground">
            View and search audit trail entries
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => handleExport('csv')}
            className="flex items-center gap-2 px-4 py-2 border border-border rounded-lg hover:bg-muted"
          >
            <Download className="h-4 w-4" />
            Export CSV
          </button>
          <button
            onClick={() => handleExport('json')}
            className="flex items-center gap-2 px-4 py-2 border border-border rounded-lg hover:bg-muted"
          >
            <Download className="h-4 w-4" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-center gap-2 mb-4">
          <Filter className="h-5 w-5 text-muted-foreground" />
          <h3 className="font-semibold">Filters</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Domain Search */}
          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">
              Domain
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={searchDomain}
                onChange={(e) => setSearchDomain(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="example.com"
                className="flex-1 px-3 py-2 border border-border rounded-lg bg-background"
              />
              <button
                onClick={handleSearch}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
              >
                <Search className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Decision Filter */}
          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">
              Decision
            </label>
            <select
              value={filters.decision}
              onChange={(e) => handleFilterChange('decision', e.target.value)}
              className="w-full px-3 py-2 border border-border rounded-lg bg-background"
            >
              <option value="">All</option>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
              <option value="block">Block</option>
              <option value="rate_limited">Rate Limited</option>
              <option value="time_restricted">Time Restricted</option>
            </select>
          </div>

          {/* Date Range */}
          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">
              Start Date
            </label>
            <input
              type="datetime-local"
              value={filters.startTime.slice(0, 16)}
              onChange={(e) =>
                handleFilterChange('startTime', new Date(e.target.value).toISOString())
              }
              className="w-full px-3 py-2 border border-border rounded-lg bg-background"
            />
          </div>

          <div>
            <label className="text-sm font-medium text-muted-foreground block mb-2">
              End Date
            </label>
            <input
              type="datetime-local"
              value={filters.endTime.slice(0, 16)}
              onChange={(e) =>
                handleFilterChange('endTime', new Date(e.target.value).toISOString())
              }
              className="w-full px-3 py-2 border border-border rounded-lg bg-background"
            />
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      {isLoading ? (
        <div className="flex items-center justify-center h-96 rounded-lg border border-border bg-card">
          <div className="text-muted-foreground">Loading audit logs...</div>
        </div>
      ) : data?.entries.length === 0 ? (
        <div className="flex items-center justify-center h-96 rounded-lg border border-border bg-card">
          <div className="text-muted-foreground">No audit entries found for the selected filters</div>
        </div>
      ) : (
        <>
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full">
              <thead className="bg-muted/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">
                    Timestamp
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">
                    Decision
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">
                    Domain
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">
                    Method
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">
                    Path
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">
                    Reason
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">
                    Agent
                  </th>
                </tr>
              </thead>
              <tbody className="bg-card divide-y divide-border">
                {data?.entries.map((entry) => (
                  <tr key={entry.entry_id} className="hover:bg-muted/50">
                    <td className="px-4 py-3 text-sm">
                      <div>{format(new Date(entry.timestamp), 'MMM dd, HH:mm:ss')}</div>
                      <div className="text-xs text-muted-foreground">
                        {format(new Date(entry.timestamp), 'yyyy')}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full ${
                          entry.decision === 'allow'
                            ? 'bg-green-100 text-green-800'
                            : 'bg-red-100 text-red-800'
                        }`}
                      >
                        {entry.decision === 'allow' ? (
                          <CheckCircle className="h-3 w-3" />
                        ) : (
                          <XCircle className="h-3 w-3" />
                        )}
                        {entry.decision}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm font-medium">{entry.domain}</td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {entry.request_method}
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground max-w-xs truncate">
                      {entry.request_path}
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground max-w-md truncate">
                      {entry.reason}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {entry.agent_id.slice(0, 8)}...
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {data && (
            <div className="flex items-center justify-between">
              <div className="text-sm text-muted-foreground">
                Showing {data.entries.length} of {data.total_count} entries
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 border border-border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <span className="px-3 py-1 text-sm text-muted-foreground">
                  Page {page}
                </span>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  disabled={!data.has_more}
                  className="px-3 py-1 border border-border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
