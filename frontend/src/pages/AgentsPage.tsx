import { useState } from "react";
import { useAgents } from "@/hooks/useApi";
import { Shield, Plus, Calendar, CheckCircle } from "lucide-react";
import { format } from "date-fns";
import { AddAgentModal } from "@/components/AddAgentModal";

export function AgentsPage() {
  const [showAddModal, setShowAddModal] = useState(false);
  const { data, isLoading, error } = useAgents();

  if (isLoading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "24rem" }}>
        <div style={{ color: "hsl(var(--muted-foreground))", fontSize: "1.125rem" }}>
          Loading agents...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "24rem" }}>
        <div style={{ fontSize: "1.125rem", color: "hsl(var(--danger))" }}>
          Error loading agents
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
            Agents
          </h2>
          <p style={{ marginTop: "0.25rem", color: "hsl(var(--muted-foreground))" }}>
            Manage and monitor your ChronoGuard agents
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            padding: "0.625rem 1rem",
            borderRadius: "0.5rem",
            color: "white",
            fontWeight: 500,
            background: "linear-gradient(to right, #C693F8, #A85FF4)",
            border: "none",
            cursor: "pointer",
            transition: "opacity 0.2s"
          }}
        >
          <Plus style={{ height: "1rem", width: "1rem" }} />
          Add Agent
        </button>
      </div>

      {/* Agents Table Card */}
      <div
        style={{
          backgroundColor: "white",
          borderRadius: "12px",
          overflow: "hidden",
          width: "100%",
          boxShadow: "var(--shadow)",
          border: "1px solid hsl(var(--border))"
        }}
      >
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ backgroundColor: "hsl(var(--muted))" }}>
                <th style={{
                  padding: "1rem 1.5rem",
                  textAlign: "left",
                  fontSize: "0.75rem",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  color: "hsl(var(--muted-foreground))",
                  whiteSpace: "nowrap"
                }}>
                  Agent Name
                </th>
                <th style={{
                  padding: "0.75rem 1.5rem",
                  textAlign: "left",
                  fontSize: "0.75rem",
                  fontWeight: 500,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  color: "hsl(var(--muted-foreground))",
                  whiteSpace: "nowrap"
                }}>
                  Status
                </th>
                <th style={{
                  padding: "0.75rem 1.5rem",
                  textAlign: "left",
                  fontSize: "0.75rem",
                  fontWeight: 500,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  color: "hsl(var(--muted-foreground))",
                  whiteSpace: "nowrap"
                }}>
                  Certificate Expiry
                </th>
                <th style={{
                  padding: "0.75rem 1.5rem",
                  textAlign: "left",
                  fontSize: "0.75rem",
                  fontWeight: 500,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  color: "hsl(var(--muted-foreground))",
                  whiteSpace: "nowrap"
                }}>
                  Policies
                </th>
                <th style={{
                  padding: "0.75rem 1.5rem",
                  textAlign: "left",
                  fontSize: "0.75rem",
                  fontWeight: 500,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  color: "hsl(var(--muted-foreground))",
                  whiteSpace: "nowrap"
                }}>
                  Last Seen
                </th>
                <th style={{
                  padding: "0.75rem 1.5rem",
                  textAlign: "left",
                  fontSize: "0.75rem",
                  fontWeight: 500,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  color: "hsl(var(--muted-foreground))",
                  whiteSpace: "nowrap"
                }}>
                  Created
                </th>
              </tr>
            </thead>
            <tbody>
              {data?.agents.map((agent, idx) => (
                <tr
                  key={agent.agent_id}
                  style={{
                    backgroundColor: "white",
                    borderTop: idx > 0 ? "1px solid hsl(var(--border))" : "none",
                    transition: "background-color 0.2s"
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = "#F9FAFB"}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = "white"}
                >
                  <td style={{ padding: "1rem 1.5rem", whiteSpace: "nowrap" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                      <div
                        style={{
                          width: "2.5rem",
                          height: "2.5rem",
                          borderRadius: "0.5rem",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          flexShrink: 0,
                          background: "rgba(99, 102, 241, 0.1)"
                        }}
                      >
                        <Shield style={{ height: "1.25rem", width: "1.25rem", color: "#6366F1" }} />
                      </div>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", color: "hsl(var(--foreground))" }}>
                          {agent.name}
                        </div>
                        <div style={{ fontSize: "0.75rem", fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", color: "hsl(var(--muted-foreground))" }}>
                          {agent.agent_id.slice(0, 16)}...
                        </div>
                      </div>
                    </div>
                  </td>
                  <td style={{ padding: "1rem 1.5rem", whiteSpace: "nowrap" }}>
                    <span
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "0.25rem",
                        padding: "0.375rem 0.75rem",
                        fontSize: "0.75rem",
                        fontWeight: 500,
                        borderRadius: "9999px",
                        backgroundColor: agent.status === "active"
                          ? "rgba(16, 185, 129, 0.1)"
                          : agent.status === "suspended"
                          ? "rgba(239, 68, 68, 0.1)"
                          : "rgba(245, 158, 11, 0.1)",
                        color: agent.status === "active"
                          ? "#10B981"
                          : agent.status === "suspended"
                          ? "#EF4444"
                          : "#F59E0B"
                      }}
                    >
                      {agent.status === "active" && <CheckCircle style={{ height: "0.75rem", width: "0.75rem" }} />}
                      <span style={{ textTransform: "capitalize" }}>{agent.status}</span>
                    </span>
                  </td>
                  <td style={{ padding: "1rem 1.5rem", whiteSpace: "nowrap" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.875rem" }}>
                      <Calendar style={{ height: "1rem", width: "1rem", color: "hsl(var(--muted-foreground))" }} />
                      <span style={{ color: "hsl(var(--foreground))" }}>
                        {format(new Date(agent.certificate_expiry), "MMM dd, yyyy")}
                      </span>
                    </div>
                  </td>
                  <td style={{ padding: "1rem 1.5rem", whiteSpace: "nowrap", fontSize: "0.875rem", color: "hsl(var(--foreground))" }}>
                    {agent.policy_ids.length} {agent.policy_ids.length === 1 ? 'policy' : 'policies'}
                  </td>
                  <td style={{ padding: "1rem 1.5rem", whiteSpace: "nowrap", fontSize: "0.875rem", color: "hsl(var(--muted-foreground))" }}>
                    {agent.last_seen_at ? format(new Date(agent.last_seen_at), "MMM dd, yyyy HH:mm") : "Never"}
                  </td>
                  <td style={{ padding: "1rem 1.5rem", whiteSpace: "nowrap", fontSize: "0.875rem", color: "hsl(var(--muted-foreground))" }}>
                    {format(new Date(agent.created_at), "MMM dd, yyyy")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {data && data.total_count > data.page_size && (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ fontSize: "0.875rem", color: "hsl(var(--muted-foreground))" }}>
            Showing {data.agents.length} of {data.total_count} agents
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button
              style={{
                padding: "0.5rem 1rem",
                borderRadius: "0.5rem",
                border: "1px solid hsl(var(--border))",
                color: "hsl(var(--muted-foreground))",
                backgroundColor: "white",
                cursor: "not-allowed",
                opacity: 0.5
              }}
              disabled
            >
              Previous
            </button>
            <button
              style={{
                padding: "0.5rem 1rem",
                borderRadius: "0.5rem",
                border: "1px solid hsl(var(--border))",
                color: "hsl(var(--foreground))",
                backgroundColor: "white",
                cursor: "pointer",
                transition: "background-color 0.2s"
              }}
            >
              Next
            </button>
          </div>
        </div>
      )}

      {/* Add Agent Modal */}
      {showAddModal && <AddAgentModal onClose={() => setShowAddModal(false)} />}
    </div>
  );
}
