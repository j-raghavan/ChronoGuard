import { useState } from "react";
import { Database, X, Loader2 } from "lucide-react";

interface SeedDataPromptProps {
  onSeed: () => Promise<void>;
  onDismiss: () => void;
}

export function SeedDataPrompt({ onSeed, onDismiss }: SeedDataPromptProps) {
  const [isSeeding, setIsSeeding] = useState(false);

  const handleSeed = async () => {
    setIsSeeding(true);
    try {
      await onSeed();
    } catch (error) {
      console.error("Failed to seed database:", error);
    } finally {
      setIsSeeding(false);
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

          <div style={{ display: "flex", gap: "0.75rem" }}>
            <button
              onClick={handleSeed}
              disabled={isSeeding}
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
                cursor: isSeeding ? "not-allowed" : "pointer",
                opacity: isSeeding ? 0.7 : 1,
                transition: "opacity 0.2s",
                boxShadow: "0 2px 4px rgba(102, 126, 234, 0.3)",
              }}
            >
              {isSeeding ? (
                <>
                  <Loader2
                    style={{
                      height: "1rem",
                      width: "1rem",
                      animation: "spin 1s linear infinite",
                    }}
                  />
                  Seeding database...
                </>
              ) : (
                <>
                  <Database style={{ height: "1rem", width: "1rem" }} />
                  Load Sample Data
                </>
              )}
            </button>
            <button
              onClick={onDismiss}
              disabled={isSeeding}
              style={{
                padding: "0.625rem 1.25rem",
                backgroundColor: "transparent",
                color: "#6b7280",
                fontSize: "0.875rem",
                fontWeight: 500,
                borderRadius: "0.5rem",
                border: "1px solid #e5e7eb",
                cursor: isSeeding ? "not-allowed" : "pointer",
                opacity: isSeeding ? 0.5 : 1,
                transition: "background-color 0.2s",
              }}
              onMouseEnter={(e) =>
                !isSeeding &&
                (e.currentTarget.style.backgroundColor = "#f9fafb")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.backgroundColor = "transparent")
              }
            >
              I'll do it later
            </button>
          </div>
        </div>
      </div>

      {/* Spinning animation for loader */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
