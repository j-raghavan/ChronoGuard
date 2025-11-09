import { useState } from "react";
import { X, Plus, Trash2, AlertCircle } from "lucide-react";
import { useCreatePolicy } from "@/hooks/useApi";

interface AddPolicyModalProps {
  onClose: () => void;
}

export function AddPolicyModal({ onClose }: AddPolicyModalProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState("1000");
  const [allowedDomains, setAllowedDomains] = useState<string[]>([""]);
  const [blockedDomains, setBlockedDomains] = useState<string[]>([""]);
  const [error, setError] = useState("");
  const createPolicy = useCreatePolicy();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!name.trim()) {
      setError("Policy name is required");
      return;
    }

    const allowed = allowedDomains.filter(d => d.trim());
    const blocked = blockedDomains.filter(d => d.trim());

    if (allowed.length === 0 && blocked.length === 0) {
      setError("At least one allowed or blocked domain is required");
      return;
    }

    try {
      await createPolicy.mutateAsync({
        name: name.trim(),
        description: description.trim(),
        priority: parseInt(priority),
        allowed_domains: allowed,
        blocked_domains: blocked,
      });
      onClose();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to create policy");
    }
  };

  const addDomain = (type: "allowed" | "blocked") => {
    if (type === "allowed") {
      setAllowedDomains([...allowedDomains, ""]);
    } else {
      setBlockedDomains([...blockedDomains, ""]);
    }
  };

  const removeDomain = (type: "allowed" | "blocked", index: number) => {
    if (type === "allowed") {
      setAllowedDomains(allowedDomains.filter((_, i) => i !== index));
    } else {
      setBlockedDomains(blockedDomains.filter((_, i) => i !== index));
    }
  };

  const updateDomain = (type: "allowed" | "blocked", index: number, value: string) => {
    if (type === "allowed") {
      const updated = [...allowedDomains];
      updated[index] = value;
      setAllowedDomains(updated);
    } else {
      const updated = [...blockedDomains];
      updated[index] = value;
      setBlockedDomains(updated);
    }
  };

  return (
    <div style={{
      position: "fixed",
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: "rgba(0, 0, 0, 0.5)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      zIndex: 1000,
      padding: "1rem"
    }}>
      <div style={{
        backgroundColor: "white",
        borderRadius: "12px",
        width: "100%",
        maxWidth: "42rem",
        maxHeight: "90vh",
        overflow: "auto",
        boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1)"
      }}>
        {/* Header */}
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "1.5rem",
          borderBottom: "1px solid hsl(var(--border))"
        }}>
          <h2 style={{ fontSize: "1.25rem", fontWeight: 600, color: "hsl(var(--foreground))" }}>
            Create New Policy
          </h2>
          <button
            onClick={onClose}
            style={{
              padding: "0.5rem",
              backgroundColor: "transparent",
              border: "none",
              cursor: "pointer",
              color: "hsl(var(--muted-foreground))",
              borderRadius: "0.25rem"
            }}
          >
            <X style={{ height: "1.25rem", width: "1.25rem" }} />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          {/* Policy Name */}
          <div>
            <label style={{
              display: "block",
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "hsl(var(--foreground))",
              marginBottom: "0.5rem"
            }}>
              Policy Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Production Access Policy"
              required
              style={{
                width: "100%",
                padding: "0.625rem 0.875rem",
                border: "1px solid hsl(var(--border))",
                borderRadius: "0.5rem",
                fontSize: "0.875rem",
                outline: "none"
              }}
            />
          </div>

          {/* Description */}
          <div>
            <label style={{
              display: "block",
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "hsl(var(--foreground))",
              marginBottom: "0.5rem"
            }}>
              Description
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe this policy..."
              rows={3}
              style={{
                width: "100%",
                padding: "0.625rem 0.875rem",
                border: "1px solid hsl(var(--border))",
                borderRadius: "0.5rem",
                fontSize: "0.875rem",
                outline: "none",
                resize: "vertical"
              }}
            />
          </div>

          {/* Priority */}
          <div>
            <label style={{
              display: "block",
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "hsl(var(--foreground))",
              marginBottom: "0.5rem"
            }}>
              Priority (lower = higher priority, must be unique)
            </label>
            <input
              type="number"
              value={priority}
              onChange={(e) => setPriority(e.target.value)}
              min="1"
              max="10000"
              style={{
                width: "100%",
                padding: "0.625rem 0.875rem",
                border: "1px solid hsl(var(--border))",
                borderRadius: "0.5rem",
                fontSize: "0.875rem",
                outline: "none"
              }}
            />
            <p style={{
              fontSize: "0.75rem",
              color: "hsl(var(--muted-foreground))",
              marginTop: "0.375rem"
            }}>
              Existing policies: 100, 200, 300, 500. Use a different number.
            </p>
          </div>

          {/* Allowed Domains */}
          <div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
              <label style={{
                fontSize: "0.875rem",
                fontWeight: 500,
                color: "hsl(var(--foreground))"
              }}>
                Allowed Domains
              </label>
              <button
                type="button"
                onClick={() => addDomain("allowed")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.25rem",
                  padding: "0.25rem 0.625rem",
                  fontSize: "0.75rem",
                  backgroundColor: "rgba(16, 185, 129, 0.1)",
                  color: "#10B981",
                  border: "none",
                  borderRadius: "0.25rem",
                  cursor: "pointer"
                }}
              >
                <Plus style={{ height: "0.875rem", width: "0.875rem" }} />
                Add
              </button>
            </div>
            {allowedDomains.map((domain, index) => (
              <div key={index} style={{ display: "flex", gap: "0.5rem", marginBottom: "0.5rem" }}>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => updateDomain("allowed", index, e.target.value)}
                  placeholder="example.com"
                  style={{
                    flex: 1,
                    padding: "0.5rem 0.75rem",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "0.5rem",
                    fontSize: "0.875rem",
                    outline: "none"
                  }}
                />
                {allowedDomains.length > 1 && (
                  <button
                    type="button"
                    onClick={() => removeDomain("allowed", index)}
                    style={{
                      padding: "0.5rem",
                      backgroundColor: "transparent",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "0.5rem",
                      cursor: "pointer",
                      color: "#EF4444"
                    }}
                  >
                    <Trash2 style={{ height: "1rem", width: "1rem" }} />
                  </button>
                )}
              </div>
            ))}
          </div>

          {/* Blocked Domains */}
          <div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
              <label style={{
                fontSize: "0.875rem",
                fontWeight: 500,
                color: "hsl(var(--foreground))"
              }}>
                Blocked Domains
              </label>
              <button
                type="button"
                onClick={() => addDomain("blocked")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.25rem",
                  padding: "0.25rem 0.625rem",
                  fontSize: "0.75rem",
                  backgroundColor: "rgba(239, 68, 68, 0.1)",
                  color: "#EF4444",
                  border: "none",
                  borderRadius: "0.25rem",
                  cursor: "pointer"
                }}
              >
                <Plus style={{ height: "0.875rem", width: "0.875rem" }} />
                Add
              </button>
            </div>
            {blockedDomains.map((domain, index) => (
              <div key={index} style={{ display: "flex", gap: "0.5rem", marginBottom: "0.5rem" }}>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => updateDomain("blocked", index, e.target.value)}
                  placeholder="admin.example.com"
                  style={{
                    flex: 1,
                    padding: "0.5rem 0.75rem",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "0.5rem",
                    fontSize: "0.875rem",
                    outline: "none"
                  }}
                />
                {blockedDomains.length > 1 && (
                  <button
                    type="button"
                    onClick={() => removeDomain("blocked", index)}
                    style={{
                      padding: "0.5rem",
                      backgroundColor: "transparent",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "0.5rem",
                      cursor: "pointer",
                      color: "#EF4444"
                    }}
                  >
                    <Trash2 style={{ height: "1rem", width: "1rem" }} />
                  </button>
                )}
              </div>
            ))}
          </div>

          {/* Error Message */}
          {error && (
            <div style={{
              display: "flex",
              alignItems: "center",
              gap: "0.75rem",
              padding: "0.75rem 1rem",
              backgroundColor: "rgba(239, 68, 68, 0.1)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              borderRadius: "0.5rem"
            }}>
              <AlertCircle style={{ height: "1.25rem", width: "1.25rem", color: "#EF4444", flexShrink: 0 }} />
              <p style={{ fontSize: "0.875rem", color: "#EF4444", margin: 0 }}>
                {error}
              </p>
            </div>
          )}

          {/* Actions */}
          <div style={{ display: "flex", gap: "0.75rem", justifyContent: "flex-end", paddingTop: "1rem", borderTop: "1px solid hsl(var(--border))" }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: "0.625rem 1.25rem",
                backgroundColor: "transparent",
                color: "hsl(var(--muted-foreground))",
                fontSize: "0.875rem",
                fontWeight: 500,
                borderRadius: "0.5rem",
                border: "1px solid hsl(var(--border))",
                cursor: "pointer"
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createPolicy.isPending}
              style={{
                padding: "0.625rem 1.25rem",
                background: "linear-gradient(to right, #6AA4E3, #6564E7)",
                color: "white",
                fontSize: "0.875rem",
                fontWeight: 600,
                borderRadius: "0.5rem",
                border: "none",
                cursor: createPolicy.isPending ? "not-allowed" : "pointer",
                opacity: createPolicy.isPending ? 0.7 : 1
              }}
            >
              {createPolicy.isPending ? "Creating..." : "Create Policy"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
