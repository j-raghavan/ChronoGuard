import { useState } from "react";
import { usePolicies } from "@/hooks/useApi";
import { FileText, Plus, CheckCircle, Lock, Unlock } from "lucide-react";
import { format } from "date-fns";
import { AddPolicyModal } from "@/components/AddPolicyModal";

export function PoliciesPage() {
  const [showAddModal, setShowAddModal] = useState(false);
  const { data, isLoading, error } = usePolicies();

  if (isLoading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "24rem" }}>
        <div style={{ color: "hsl(var(--muted-foreground))", fontSize: "1.125rem" }}>
          Loading policies...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "24rem" }}>
        <div style={{ fontSize: "1.125rem", color: "hsl(var(--danger))" }}>
          Error loading policies
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
            Policies
          </h2>
          <p style={{ marginTop: "0.25rem", color: "hsl(var(--muted-foreground))" }}>
            Create and manage access policies and rules
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
            background: "linear-gradient(to right, #6AA4E3, #6564E7)",
            border: "none",
            cursor: "pointer",
            transition: "opacity 0.2s"
          }}
        >
          <Plus style={{ height: "1rem", width: "1rem" }} />
          Create Policy
        </button>
      </div>

      {/* Policies Grid */}
      <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
        {data?.policies.map((policy) => (
          <div
            key={policy.policy_id}
            style={{
              backgroundColor: "white",
              borderRadius: "12px",
              padding: "1.5rem",
              boxShadow: "var(--shadow)",
              border: "1px solid hsl(var(--border))",
              transition: "box-shadow 0.2s"
            }}
          >
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: "1rem", flex: 1 }}>
                <div
                  style={{
                    width: "3rem",
                    height: "3rem",
                    borderRadius: "0.5rem",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                    background: "rgba(34, 211, 238, 0.1)"
                  }}
                >
                  <FileText style={{ height: "1.5rem", width: "1.5rem", color: "#22D3EE" }} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <h3 style={{ fontSize: "1.125rem", fontWeight: 600, color: "hsl(var(--foreground))" }}>
                    {policy.name}
                  </h3>
                  <p style={{ fontSize: "0.875rem", marginTop: "0.25rem", color: "hsl(var(--muted-foreground))" }}>
                    {policy.description}
                  </p>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginTop: "0.75rem", flexWrap: "wrap" }}>
                    <span
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "0.25rem",
                        padding: "0.375rem 0.75rem",
                        fontSize: "0.75rem",
                        fontWeight: 500,
                        borderRadius: "9999px",
                        backgroundColor: policy.status === "active"
                          ? "rgba(16, 185, 129, 0.1)"
                          : "rgba(107, 114, 128, 0.1)",
                        color: policy.status === "active" ? "#10B981" : "#6B7280"
                      }}
                    >
                      {policy.status === "active" && <CheckCircle style={{ height: "0.75rem", width: "0.75rem" }} />}
                      <span style={{ textTransform: "capitalize" }}>{policy.status}</span>
                    </span>
                    <span
                      style={{
                        padding: "0.375rem 0.75rem",
                        fontSize: "0.75rem",
                        fontWeight: 500,
                        borderRadius: "9999px",
                        backgroundColor: "hsl(var(--muted))",
                        color: "hsl(var(--foreground))"
                      }}
                    >
                      Priority: {policy.priority}
                    </span>
                    <span
                      style={{
                        padding: "0.375rem 0.75rem",
                        fontSize: "0.75rem",
                        fontWeight: 500,
                        borderRadius: "9999px",
                        backgroundColor: "hsl(var(--muted))",
                        color: "hsl(var(--foreground))"
                      }}
                    >
                      {policy.rules.length} {policy.rules.length === 1 ? 'rule' : 'rules'}
                    </span>
                    <span
                      style={{
                        padding: "0.375rem 0.75rem",
                        fontSize: "0.75rem",
                        fontWeight: 500,
                        borderRadius: "9999px",
                        backgroundColor: "rgba(99, 102, 241, 0.1)",
                        color: "#6366F1"
                      }}
                    >
                      {policy.allowed_domains.length} allowed, {policy.blocked_domains.length} blocked
                    </span>
                  </div>
                </div>
              </div>
              <div style={{ textAlign: "right", flexShrink: 0, marginLeft: "1rem" }}>
                <div style={{ fontSize: "0.875rem", color: "hsl(var(--muted-foreground))" }}>
                  {format(new Date(policy.created_at), "MMM dd, yyyy")}
                </div>
                <div style={{ fontSize: "0.75rem", marginTop: "0.25rem", color: "hsl(var(--muted-foreground))" }}>
                  v{policy.version}
                </div>
              </div>
            </div>

            {/* Allowed Domains */}
            {policy.allowed_domains.length > 0 && (
              <div style={{ marginTop: "1rem", paddingTop: "1rem", borderTop: "1px solid hsl(var(--border))" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.75rem" }}>
                  <Unlock style={{ height: "1rem", width: "1rem", color: "#10B981" }} />
                  <div style={{ fontSize: "0.875rem", fontWeight: 500, color: "hsl(var(--foreground))" }}>
                    Allowed Domains
                  </div>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
                  {policy.allowed_domains.map((domain, idx) => (
                    <span
                      key={idx}
                      style={{
                        padding: "0.375rem 0.75rem",
                        fontSize: "0.75rem",
                        fontWeight: 500,
                        borderRadius: "0.5rem",
                        backgroundColor: "rgba(16, 185, 129, 0.1)",
                        color: "#10B981"
                      }}
                    >
                      {domain}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Blocked Domains */}
            {policy.blocked_domains.length > 0 && (
              <div style={{ marginTop: "0.75rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.75rem" }}>
                  <Lock style={{ height: "1rem", width: "1rem", color: "#EF4444" }} />
                  <div style={{ fontSize: "0.875rem", fontWeight: 500, color: "hsl(var(--foreground))" }}>
                    Blocked Domains
                  </div>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
                  {policy.blocked_domains.map((domain, idx) => (
                    <span
                      key={idx}
                      style={{
                        padding: "0.375rem 0.75rem",
                        fontSize: "0.75rem",
                        fontWeight: 500,
                        borderRadius: "0.5rem",
                        backgroundColor: "rgba(239, 68, 68, 0.1)",
                        color: "#EF4444"
                      }}
                    >
                      {domain}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Add Policy Modal */}
      {showAddModal && <AddPolicyModal onClose={() => setShowAddModal(false)} />}
    </div>
  );
}
