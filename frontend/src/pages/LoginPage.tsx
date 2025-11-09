import { useState } from "react";
import { Shield, Lock, AlertCircle } from "lucide-react";

interface LoginPageProps {
  onLogin: () => void;
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    // Get default password from environment
    const defaultPassword = import.meta.env.VITE_DEFAULT_PASSWORD || "chronoguard-admin-2025";

    if (password === defaultPassword) {
      // Set authentication in localStorage
      localStorage.setItem("isAuthenticated", "true");
      localStorage.setItem("tenantId", import.meta.env.VITE_DEFAULT_TENANT_ID || "550e8400-e29b-41d4-a716-446655440001");
      localStorage.setItem("userId", import.meta.env.VITE_DEFAULT_USER_ID || "550e8400-e29b-41d4-a716-446655440002");

      // Simulate API call delay
      setTimeout(() => {
        setIsLoading(false);
        onLogin();
      }, 500);
    } else {
      setIsLoading(false);
      setError("Invalid password. Please try again.");
    }
  };

  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
      padding: "1rem"
    }}>
      <div style={{
        width: "100%",
        maxWidth: "28rem",
        backgroundColor: "white",
        borderRadius: "16px",
        padding: "3rem 2rem",
        boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)"
      }}>
        {/* Logo and Title */}
        <div style={{ textAlign: "center", marginBottom: "2rem" }}>
          <div style={{
            width: "5rem",
            height: "5rem",
            margin: "0 auto 1.5rem",
            background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
            borderRadius: "16px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 10px 15px -3px rgba(102, 126, 234, 0.4)"
          }}>
            <Shield style={{ height: "2.5rem", width: "2.5rem", color: "white" }} />
          </div>
          <h1 style={{
            fontSize: "1.875rem",
            fontWeight: "bold",
            color: "#1a202c",
            marginBottom: "0.5rem"
          }}>
            ChronoGuard
          </h1>
          <p style={{
            fontSize: "0.875rem",
            color: "#718096"
          }}>
            Time-Based Access Control System
          </p>
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          <div>
            <label style={{
              display: "block",
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "#4a5568",
              marginBottom: "0.5rem"
            }}>
              Password
            </label>
            <div style={{ position: "relative" }}>
              <Lock style={{
                position: "absolute",
                left: "1rem",
                top: "50%",
                transform: "translateY(-50%)",
                height: "1.25rem",
                width: "1.25rem",
                color: "#a0aec0"
              }} />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
                style={{
                  width: "100%",
                  padding: "0.75rem 1rem 0.75rem 3rem",
                  border: "2px solid #e2e8f0",
                  borderRadius: "0.5rem",
                  fontSize: "1rem",
                  outline: "none",
                  transition: "border-color 0.2s",
                  backgroundColor: "white"
                }}
                onFocus={(e) => e.currentTarget.style.borderColor = "#667eea"}
                onBlur={(e) => e.currentTarget.style.borderColor = "#e2e8f0"}
              />
            </div>
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

          {/* Login Button */}
          <button
            type="submit"
            disabled={isLoading}
            style={{
              width: "100%",
              padding: "0.875rem 1.5rem",
              background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
              color: "white",
              fontSize: "1rem",
              fontWeight: 600,
              borderRadius: "0.5rem",
              border: "none",
              cursor: isLoading ? "not-allowed" : "pointer",
              opacity: isLoading ? 0.7 : 1,
              transition: "opacity 0.2s",
              boxShadow: "0 4px 6px -1px rgba(102, 126, 234, 0.3)"
            }}
          >
            {isLoading ? "Signing in..." : "Sign In"}
          </button>

          {/* Help Text */}
          <div style={{
            textAlign: "center",
            fontSize: "0.75rem",
            color: "#a0aec0",
            marginTop: "0.5rem"
          }}>
            Default password: <code style={{
              backgroundColor: "#f7fafc",
              padding: "0.125rem 0.375rem",
              borderRadius: "0.25rem",
              fontFamily: "monospace",
              color: "#4a5568"
            }}>chronoguard-admin-2025</code>
          </div>
        </form>
      </div>
    </div>
  );
}
