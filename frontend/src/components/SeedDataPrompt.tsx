import { useState } from "react";
import { Database, X, Copy, CheckCircle2 } from "lucide-react";

interface SeedDataPromptProps {
  seedCommand: string;
  onConfirmSeed: () => Promise<void> | void;
  onDismiss: () => void;
  docsUrl?: string;
}

export function SeedDataPrompt({
  seedCommand,
  onConfirmSeed,
  onDismiss,
  docsUrl,
}: SeedDataPromptProps) {
  const [copied, setCopied] = useState(false);
  const [isConfirming, setIsConfirming] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(seedCommand);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error("Failed to copy seed command", error);
    }
  };

  const handleConfirmSeed = async () => {
    setIsConfirming(true);
    try {
      await onConfirmSeed();
    } finally {
      setIsConfirming(false);
    }
  };

  return (
    <div
      style={{
        backgroundColor: "white",
        border: "2px solid #6366F1",
        borderRadius: "12px",
        padding: "1.5rem",
        boxShadow: "0 10px 15px -3px rgba(99, 102, 241, 0.1)",
        marginBottom: "1.5rem",
        position: "relative",
      }}
    >
      {/* Close button */}
      <button
        onClick={onDismiss}
        style={{
          position: "absolute",
          top: "1rem",
          right: "1rem",
          padding: "0.25rem",
          backgroundColor: "transparent",
          border: "none",
          cursor: "pointer",
          color: "#9ca3af",
          borderRadius: "0.25rem",
        }}
        onMouseEnter={(e) =>
          (e.currentTarget.style.backgroundColor = "#f3f4f6")
        }
        onMouseLeave={(e) =>
          (e.currentTarget.style.backgroundColor = "transparent")
        }
      >
        <X style={{ height: "1.25rem", width: "1.25rem" }} />
      </button>

      <div style={{ display: "flex", gap: "1rem", alignItems: "flex-start" }}>
        <div
          style={{
            width: "3rem",
            height: "3rem",
            borderRadius: "0.75rem",
            background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Database
            style={{ height: "1.5rem", width: "1.5rem", color: "white" }}
          />
        </div>

        <div style={{ flex: 1, paddingRight: "2rem" }}>
          <h3
            style={{
              fontSize: "1.125rem",
              fontWeight: 600,
              color: "#1f2937",
              marginBottom: "0.5rem",
            }}
          >
            Your database is empty
          </h3>
          <p
            style={{
              fontSize: "0.875rem",
              color: "#6b7280",
              marginBottom: "1rem",
              lineHeight: 1.6,
            }}
          >
            Would you like to populate it with sample data? This will add 8
            agents, 4 policies, and ~2,000 audit entries to help you explore
            ChronoGuard's features.
          </p>

          <div
            style={{
              backgroundColor: "#f3f4f6",
              borderRadius: "0.75rem",
              border: "1px solid #e5e7eb",
              padding: "1rem",
              marginBottom: "1rem",
            }}
          >
            <p
              style={{
                fontSize: "0.85rem",
                color: "#4b5563",
                marginBottom: "0.75rem",
              }}
            >
              Run the following command from the project root to seed local
              data:
            </p>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.75rem",
                backgroundColor: "white",
                borderRadius: "0.5rem",
                border: "1px dashed #d1d5db",
                padding: "0.75rem 1rem",
                fontFamily: "monospace",
                fontSize: "0.85rem",
                color: "#111827",
              }}
            >
              <code style={{ flex: 1, whiteSpace: "pre-wrap" }}>
                {seedCommand}
              </code>
              <button
                onClick={handleCopy}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.25rem",
                  border: "none",
                  backgroundColor: "#eef2ff",
                  color: "#4f46e5",
                  padding: "0.4rem 0.75rem",
                  borderRadius: "0.5rem",
                  cursor: "pointer",
                  fontSize: "0.75rem",
                  fontWeight: 600,
                }}
              >
                {copied ? (
                  <>
                    <CheckCircle2 style={{ height: "1rem", width: "1rem" }} />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy style={{ height: "1rem", width: "1rem" }} />
                    Copy
                  </>
                )}
              </button>
            </div>
            {docsUrl && (
              <p
                style={{
                  fontSize: "0.75rem",
                  color: "#6b7280",
                  marginTop: "0.5rem",
                }}
              >
                Need help?{" "}
                <a
                  href={docsUrl}
                  style={{ color: "#4f46e5", textDecoration: "underline" }}
                >
                  Read the seeding guide
                </a>
                .
              </p>
            )}
          </div>

          <div style={{ display: "flex", gap: "0.75rem" }}>
            <button
              onClick={handleConfirmSeed}
              disabled={isConfirming}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
                padding: "0.625rem 1.25rem",
                background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
                color: "white",
                fontSize: "0.875rem",
                fontWeight: 600,
                borderRadius: "0.5rem",
                border: "none",
                cursor: isConfirming ? "not-allowed" : "pointer",
                opacity: isConfirming ? 0.7 : 1,
                transition: "opacity 0.2s",
                boxShadow: "0 2px 4px rgba(102, 126, 234, 0.3)",
              }}
            >
              {isConfirming ? (
                <>
                  <CheckCircle2 style={{ height: "1rem", width: "1rem" }} />
                  Checking data...
                </>
              ) : (
                <>
                  <Database style={{ height: "1rem", width: "1rem" }} />
                  I've seeded the data
                </>
              )}
            </button>
            <button
              onClick={onDismiss}
              disabled={isConfirming}
              style={{
                padding: "0.625rem 1.25rem",
                backgroundColor: "transparent",
                color: "#6b7280",
                fontSize: "0.875rem",
                fontWeight: 500,
                borderRadius: "0.5rem",
                border: "1px solid #e5e7eb",
                cursor: isConfirming ? "not-allowed" : "pointer",
                opacity: isConfirming ? 0.5 : 1,
                transition: "background-color 0.2s",
              }}
              onMouseEnter={(e) =>
                !isConfirming &&
                (e.currentTarget.style.backgroundColor = "#f9fafb")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.backgroundColor = "transparent")
              }
            >
              Dismiss
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
