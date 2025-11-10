import { useState } from "react";
import { X, Upload, AlertCircle } from "lucide-react";
import { useCreateAgent } from "@/hooks/useApi";

interface AddAgentModalProps {
  onClose: () => void;
}

export function AddAgentModal({ onClose }: AddAgentModalProps) {
  const [name, setName] = useState("");
  const [certificate, setCertificate] = useState("");
  const [error, setError] = useState("");
  const createAgent = useCreateAgent();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!name.trim()) {
      setError("Agent name is required");
      return;
    }

    if (!certificate.trim()) {
      setError("Certificate is required");
      return;
    }

    // Clean up certificate - remove leading/trailing whitespace from each line
    const cleanedCert = certificate
      .split("\n")
      .map((line) => line.trim())
      .join("\n")
      .trim();

    try {
      await createAgent.mutateAsync({
        name: name.trim(),
        certificate_pem: cleanedCert,
        metadata: {
          created_via: "ui",
          created_at: new Date().toISOString(),
        },
      });
      onClose();
    } catch (err: unknown) {
      const errorMessage =
        (err as { response?: { data?: { detail?: string } } }).response?.data
          ?.detail || "Failed to create agent";
      setError(errorMessage);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setCertificate(event.target?.result as string);
      };
      reader.readAsText(file);
    }
  };

  return (
    <div
      style={{
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
        padding: "1rem",
      }}
    >
      <div
        style={{
          backgroundColor: "white",
          borderRadius: "12px",
          width: "100%",
          maxWidth: "32rem",
          maxHeight: "90vh",
          overflow: "auto",
          boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1)",
        }}
      >
        {/* Header */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "1.5rem",
            borderBottom: "1px solid hsl(var(--border))",
          }}
        >
          <h2
            style={{
              fontSize: "1.25rem",
              fontWeight: 600,
              color: "hsl(var(--foreground))",
            }}
          >
            Add New Agent
          </h2>
          <button
            onClick={onClose}
            style={{
              padding: "0.5rem",
              backgroundColor: "transparent",
              border: "none",
              cursor: "pointer",
              color: "hsl(var(--muted-foreground))",
              borderRadius: "0.25rem",
            }}
          >
            <X style={{ height: "1.25rem", width: "1.25rem" }} />
          </button>
        </div>

        {/* Form */}
        <form
          onSubmit={handleSubmit}
          style={{
            padding: "1.5rem",
            display: "flex",
            flexDirection: "column",
            gap: "1.5rem",
          }}
        >
          {/* Agent Name */}
          <div>
            <label
              style={{
                display: "block",
                fontSize: "0.875rem",
                fontWeight: 500,
                color: "hsl(var(--foreground))",
                marginBottom: "0.5rem",
              }}
            >
              Agent Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., production-agent-01"
              required
              style={{
                width: "100%",
                padding: "0.625rem 0.875rem",
                border: "1px solid hsl(var(--border))",
                borderRadius: "0.5rem",
                fontSize: "0.875rem",
                outline: "none",
                backgroundColor: "white",
              }}
            />
          </div>

          {/* Certificate */}
          <div>
            <label
              style={{
                display: "block",
                fontSize: "0.875rem",
                fontWeight: 500,
                color: "hsl(var(--foreground))",
                marginBottom: "0.5rem",
              }}
            >
              X.509 Certificate (PEM format) *
            </label>
            <textarea
              value={certificate}
              onChange={(e) => setCertificate(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              required
              rows={8}
              style={{
                width: "100%",
                padding: "0.625rem 0.875rem",
                border: "1px solid hsl(var(--border))",
                borderRadius: "0.5rem",
                fontSize: "0.75rem",
                fontFamily: "monospace",
                outline: "none",
                resize: "vertical",
                backgroundColor: "white",
              }}
            />
            <div style={{ marginTop: "0.5rem" }}>
              <label
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  padding: "0.5rem 1rem",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "0.5rem",
                  fontSize: "0.875rem",
                  cursor: "pointer",
                  backgroundColor: "white",
                  color: "hsl(var(--foreground))",
                }}
              >
                <Upload style={{ height: "1rem", width: "1rem" }} />
                Upload Certificate File
                <input
                  type="file"
                  accept=".pem,.crt,.cer"
                  onChange={handleFileUpload}
                  style={{ display: "none" }}
                />
              </label>
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.75rem",
                padding: "0.75rem 1rem",
                backgroundColor: "rgba(239, 68, 68, 0.1)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                borderRadius: "0.5rem",
              }}
            >
              <AlertCircle
                style={{
                  height: "1.25rem",
                  width: "1.25rem",
                  color: "#EF4444",
                  flexShrink: 0,
                }}
              />
              <p style={{ fontSize: "0.875rem", color: "#EF4444", margin: 0 }}>
                {error}
              </p>
            </div>
          )}

          {/* Actions */}
          <div
            style={{
              display: "flex",
              gap: "0.75rem",
              justifyContent: "flex-end",
              paddingTop: "1rem",
              borderTop: "1px solid hsl(var(--border))",
            }}
          >
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
                cursor: "pointer",
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createAgent.isPending}
              style={{
                padding: "0.625rem 1.25rem",
                background: "linear-gradient(to right, #C693F8, #A85FF4)",
                color: "white",
                fontSize: "0.875rem",
                fontWeight: 600,
                borderRadius: "0.5rem",
                border: "none",
                cursor: createAgent.isPending ? "not-allowed" : "pointer",
                opacity: createAgent.isPending ? 0.7 : 1,
              }}
            >
              {createAgent.isPending ? "Creating..." : "Create Agent"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
