import { useState, useEffect, useCallback } from "react";
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  useNavigate,
} from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Layout } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { AgentsPage } from "./pages/AgentsPage";
import { PoliciesPage } from "./pages/PoliciesPage";
import { AuditPage } from "./pages/AuditPage";
import { LoginPage } from "./pages/LoginPage";
import { authApi } from "./services/api";

// Wrapper component to handle navigation after login
function AppContent() {
  const [authState, setAuthState] = useState<"checking" | "authenticated" | "unauthenticated">(
    "checking",
  );
  const navigate = useNavigate();

  // Create a query client inside component so we can clear it
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            refetchOnWindowFocus: true,
            retry: 1,
            staleTime: 5000, // 5 seconds - shorter cache to see fresh data
          },
        },
      }),
  );

  const handleLogin = useCallback(() => {
    queryClient.clear();
    setAuthState("authenticated");
    navigate("/");
  }, [navigate, queryClient]);

  const handleLogout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch (error) {
      console.error("Failed to log out", error);
    } finally {
      queryClient.clear();
      setAuthState("unauthenticated");
      navigate("/");
    }
  }, [navigate, queryClient]);

  useEffect(() => {
    let cancelled = false;

    const checkSession = async () => {
      try {
        await authApi.session();
        if (!cancelled) {
          setAuthState("authenticated");
        }
      } catch {
        if (!cancelled) {
          setAuthState("unauthenticated");
        }
      }
    };

    checkSession().catch((error) => {
      console.error("Failed to verify session", error);
      setAuthState("unauthenticated");
    });

    return () => {
      cancelled = true;
    };
  }, []);

  if (authState === "checking") {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "hsl(var(--muted-foreground))",
          fontSize: "1rem",
        }}
      >
        Checking session...
      </div>
    );
  }

  if (authState === "unauthenticated") {
    return <LoginPage onLogin={handleLogin} />;
  }

  return (
    <QueryClientProvider client={queryClient}>
      <Routes>
        <Route path="/" element={<Layout onLogout={handleLogout} />}>
          <Route index element={<Dashboard />} />
          <Route path="agents" element={<AgentsPage />} />
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="audit" element={<AuditPage />} />
          {/* Redirect any unknown routes to dashboard */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </QueryClientProvider>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}

export default App;
