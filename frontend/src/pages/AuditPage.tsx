import { useState } from "react";
import { useAuditQuery } from "@/hooks/useApi";
import { format, subDays } from "date-fns";
import { Search, Download, Filter, CheckCircle, XCircle } from "lucide-react";
import { auditApi } from "@/services/api";

export function AuditPage() {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({
    decision: "",
    domain: "",
    startTime: subDays(new Date(), 7).toISOString(),
    endTime: new Date().toISOString(),
  });
  const [searchDomain, setSearchDomain] = useState("");

  // Get tenant ID from localStorage
  const tenantId = localStorage.getItem("tenantId") || "";

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

  const handleExport = async (format: "csv" | "json") => {
    try {
      const response = await auditApi.export(
        format,
        filters.startTime,
        filters.endTime,
      );
      const blob = new Blob([response.data], {
        type: format === "csv" ? "text/csv" : "application/json",
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `audit_export_${format}_${Date.now()}.${format}`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Export failed:", error);
    }
  };

  if (error) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "24rem" }}>
        <div style={{ color: "hsl(var(--danger))" }}>
          Error loading audit logs: {error.message}
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem", width: "100%", maxWidth: "100%" }}>
      {/* Page Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%" }}>
        <div>
          <h2 style={{ fontSize: "1.875rem", fontWeight: "bold", letterSpacing: "-0.025em", color: "hsl(var(--foreground))" }}>
            Audit Log
          </h2>
          <p style={{ color: "hsl(var(--muted-foreground))" }}>
            View and search audit trail entries
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button
            onClick={() => handleExport("csv")}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              padding: "0.5rem 1rem",
              border: "1px solid hsl(var(--border))",
              borderRadius: "0.5rem",
              backgroundColor: "white",
              cursor: "pointer",
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "hsl(var(--foreground))",
              transition: "background-color 0.2s"
            }}
          >
            <Download style={{ height: "1rem", width: "1rem" }} />
            Export CSV
          </button>
          <button
            onClick={() => handleExport("json")}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              padding: "0.5rem 1rem",
              border: "1px solid hsl(var(--border))",
              borderRadius: "0.5rem",
              backgroundColor: "white",
              cursor: "pointer",
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "hsl(var(--foreground))",
              transition: "background-color 0.2s"
            }}
          >
            <Download style={{ height: "1rem", width: "1rem" }} />
            Export JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{
        borderRadius: "0.5rem",
        border: "1px solid hsl(var(--border))",
        backgroundColor: "white",
        padding: "1rem"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
          <Filter style={{ height: "1.25rem", width: "1.25rem", color: "hsl(var(--muted-foreground))" }} />
          <h3 style={{ fontWeight: 600, color: "hsl(var(--foreground))" }}>Filters</h3>
        </div>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "1rem"
        }}>
          {/* Domain Search */}
          <div>
            <label style={{
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "hsl(var(--muted-foreground))",
              display: "block",
              marginBottom: "0.5rem"
            }}>
              Domain
            </label>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <input
                type="text"
                value={searchDomain}
                onChange={(e) => setSearchDomain(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                placeholder="example.com"
                style={{
                  flex: 1,
                  padding: "0.5rem 0.75rem",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "0.5rem",
                  backgroundColor: "hsl(var(--background))",
                  fontSize: "0.875rem",
                  outline: "none"
                }}
              />
              <button
                onClick={handleSearch}
                style={{
                  padding: "0.5rem 1rem",
                  background: "hsl(var(--primary))",
                  color: "white",
                  borderRadius: "0.5rem",
                  border: "none",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center"
                }}
              >
                <Search style={{ height: "1rem", width: "1rem" }} />
              </button>
            </div>
          </div>

          {/* Decision Filter */}
          <div>
            <label style={{
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "hsl(var(--muted-foreground))",
              display: "block",
              marginBottom: "0.5rem"
            }}>
              Decision
            </label>
            <select
              value={filters.decision}
              onChange={(e) => handleFilterChange("decision", e.target.value)}
              style={{
                width: "100%",
                padding: "0.5rem 0.75rem",
                border: "1px solid hsl(var(--border))",
                borderRadius: "0.5rem",
                backgroundColor: "hsl(var(--background))",
                fontSize: "0.875rem",
                outline: "none",
                cursor: "pointer"
              }}
            >
              <option value="">All</option>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </select>
          </div>

          {/* Start Date */}
          <div>
            <label style={{
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "hsl(var(--muted-foreground))",
              display: "block",
              marginBottom: "0.5rem"
            }}>
              Start Date
            </label>
            <input
              type="datetime-local"
              value={filters.startTime.slice(0, 16)}
              onChange={(e) =>
                handleFilterChange(
                  "startTime",
                  new Date(e.target.value).toISOString(),
                )
              }
              style={{
                width: "100%",
                padding: "0.5rem 0.75rem",
                border: "1px solid hsl(var(--border))",
                borderRadius: "0.5rem",
                backgroundColor: "hsl(var(--background))",
                fontSize: "0.875rem",
                outline: "none"
              }}
            />
          </div>

          {/* End Date */}
          <div>
            <label style={{
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "hsl(var(--muted-foreground))",
              display: "block",
              marginBottom: "0.5rem"
            }}>
              End Date
            </label>
            <input
              type="datetime-local"
              value={filters.endTime.slice(0, 16)}
              onChange={(e) =>
                handleFilterChange(
                  "endTime",
                  new Date(e.target.value).toISOString(),
                )
              }
              style={{
                width: "100%",
                padding: "0.5rem 0.75rem",
                border: "1px solid hsl(var(--border))",
                borderRadius: "0.5rem",
                backgroundColor: "hsl(var(--background))",
                fontSize: "0.875rem",
                outline: "none"
              }}
            />
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      {isLoading ? (
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "24rem",
          borderRadius: "0.5rem",
          border: "1px solid hsl(var(--border))",
          backgroundColor: "white"
        }}>
          <div style={{ color: "hsl(var(--muted-foreground))" }}>Loading audit logs...</div>
        </div>
      ) : data?.entries.length === 0 ? (
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "24rem",
          borderRadius: "0.5rem",
          border: "1px solid hsl(var(--border))",
          backgroundColor: "white"
        }}>
          <div style={{ color: "hsl(var(--muted-foreground))" }}>
            No audit entries found for the selected filters
          </div>
        </div>
      ) : (
        <>
          <div style={{
            borderRadius: "12px",
            border: "1px solid hsl(var(--border))",
            overflow: "hidden",
            backgroundColor: "white",
            boxShadow: "var(--shadow)"
          }}>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ backgroundColor: "hsl(var(--muted))" }}>
                    <th style={{
                      padding: "0.75rem 1rem",
                      textAlign: "left",
                      fontSize: "0.75rem",
                      fontWeight: 500,
                      color: "hsl(var(--muted-foreground))",
                      textTransform: "uppercase",
                      whiteSpace: "nowrap"
                    }}>
                      Timestamp
                    </th>
                    <th style={{
                      padding: "0.75rem 1rem",
                      textAlign: "left",
                      fontSize: "0.75rem",
                      fontWeight: 500,
                      color: "hsl(var(--muted-foreground))",
                      textTransform: "uppercase",
                      whiteSpace: "nowrap"
                    }}>
                      Decision
                    </th>
                    <th style={{
                      padding: "0.75rem 1rem",
                      textAlign: "left",
                      fontSize: "0.75rem",
                      fontWeight: 500,
                      color: "hsl(var(--muted-foreground))",
                      textTransform: "uppercase",
                      whiteSpace: "nowrap"
                    }}>
                      Domain
                    </th>
                    <th style={{
                      padding: "0.75rem 1rem",
                      textAlign: "left",
                      fontSize: "0.75rem",
                      fontWeight: 500,
                      color: "hsl(var(--muted-foreground))",
                      textTransform: "uppercase",
                      whiteSpace: "nowrap"
                    }}>
                      Method
                    </th>
                    <th style={{
                      padding: "0.75rem 1rem",
                      textAlign: "left",
                      fontSize: "0.75rem",
                      fontWeight: 500,
                      color: "hsl(var(--muted-foreground))",
                      textTransform: "uppercase",
                      whiteSpace: "nowrap"
                    }}>
                      Path
                    </th>
                    <th style={{
                      padding: "0.75rem 1rem",
                      textAlign: "left",
                      fontSize: "0.75rem",
                      fontWeight: 500,
                      color: "hsl(var(--muted-foreground))",
                      textTransform: "uppercase",
                      whiteSpace: "nowrap"
                    }}>
                      Reason
                    </th>
                    <th style={{
                      padding: "0.75rem 1rem",
                      textAlign: "left",
                      fontSize: "0.75rem",
                      fontWeight: 500,
                      color: "hsl(var(--muted-foreground))",
                      textTransform: "uppercase",
                      whiteSpace: "nowrap"
                    }}>
                      Agent
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data?.entries.map((entry, idx) => (
                    <tr
                      key={entry.entry_id}
                      style={{
                        backgroundColor: "white",
                        borderTop: idx > 0 ? "1px solid hsl(var(--border))" : "none",
                        transition: "background-color 0.2s"
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.backgroundColor = "#F9FAFB"}
                      onMouseLeave={(e) => e.currentTarget.style.backgroundColor = "white"}
                    >
                      <td style={{ padding: "0.75rem 1rem", fontSize: "0.875rem", whiteSpace: "nowrap" }}>
                        <div style={{ color: "hsl(var(--foreground))" }}>
                          {format(new Date(entry.timestamp), "MMM dd, HH:mm:ss")}
                        </div>
                        <div style={{ fontSize: "0.75rem", color: "hsl(var(--muted-foreground))" }}>
                          {format(new Date(entry.timestamp), "yyyy")}
                        </div>
                      </td>
                      <td style={{ padding: "0.75rem 1rem", whiteSpace: "nowrap" }}>
                        <span
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "0.25rem",
                            padding: "0.375rem 0.75rem",
                            fontSize: "0.75rem",
                            fontWeight: 500,
                            borderRadius: "9999px",
                            backgroundColor: entry.decision === "allow"
                              ? "rgba(16, 185, 129, 0.1)"
                              : "rgba(239, 68, 68, 0.1)",
                            color: entry.decision === "allow" ? "#10B981" : "#EF4444"
                          }}
                        >
                          {entry.decision === "allow" ? (
                            <CheckCircle style={{ height: "0.75rem", width: "0.75rem" }} />
                          ) : (
                            <XCircle style={{ height: "0.75rem", width: "0.75rem" }} />
                          )}
                          <span style={{ textTransform: "capitalize" }}>{entry.decision}</span>
                        </span>
                      </td>
                      <td style={{
                        padding: "0.75rem 1rem",
                        fontSize: "0.875rem",
                        fontWeight: 500,
                        color: "hsl(var(--foreground))",
                        whiteSpace: "nowrap"
                      }}>
                        {entry.domain}
                      </td>
                      <td style={{
                        padding: "0.75rem 1rem",
                        fontSize: "0.875rem",
                        color: "hsl(var(--muted-foreground))",
                        whiteSpace: "nowrap"
                      }}>
                        {entry.request_method}
                      </td>
                      <td style={{
                        padding: "0.75rem 1rem",
                        fontSize: "0.875rem",
                        color: "hsl(var(--muted-foreground))",
                        maxWidth: "20rem",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap"
                      }}>
                        {entry.request_path}
                      </td>
                      <td style={{
                        padding: "0.75rem 1rem",
                        fontSize: "0.875rem",
                        color: "hsl(var(--muted-foreground))",
                        maxWidth: "24rem",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap"
                      }}>
                        {entry.reason}
                      </td>
                      <td style={{
                        padding: "0.75rem 1rem",
                        fontSize: "0.75rem",
                        color: "hsl(var(--muted-foreground))",
                        fontFamily: "monospace",
                        whiteSpace: "nowrap"
                      }}>
                        {entry.agent_id.slice(0, 8)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination */}
          {data && (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ fontSize: "0.875rem", color: "hsl(var(--muted-foreground))" }}>
                Showing {data.entries.length} of {data.total_count} entries
              </div>
              <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  style={{
                    padding: "0.5rem 0.75rem",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "0.5rem",
                    backgroundColor: "white",
                    cursor: page === 1 ? "not-allowed" : "pointer",
                    opacity: page === 1 ? 0.5 : 1,
                    fontSize: "0.875rem",
                    color: "hsl(var(--foreground))"
                  }}
                >
                  Previous
                </button>
                <span style={{ padding: "0.5rem 0.75rem", fontSize: "0.875rem", color: "hsl(var(--muted-foreground))" }}>
                  Page {page}
                </span>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  disabled={!data.has_more}
                  style={{
                    padding: "0.5rem 0.75rem",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "0.5rem",
                    backgroundColor: "white",
                    cursor: data.has_more ? "pointer" : "not-allowed",
                    opacity: data.has_more ? 1 : 0.5,
                    fontSize: "0.875rem",
                    color: "hsl(var(--foreground))"
                  }}
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
