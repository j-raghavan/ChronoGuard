import { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Layout } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { AgentsPage } from "./pages/AgentsPage";
import { PoliciesPage } from "./pages/PoliciesPage";
import { AuditPage } from "./pages/AuditPage";
import { LoginPage } from "./pages/LoginPage";

// Wrapper component to handle navigation after login
function AppContent() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const navigate = useNavigate();

  // Create a query client inside component so we can clear it
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: true,
        retry: 1,
        staleTime: 5000, // 5 seconds - shorter cache to see fresh data
      },
    },
  }));

  useEffect(() => {
    // Check if user is already authenticated
    const authStatus = localStorage.getItem("isAuthenticated");
    setIsAuthenticated(authStatus === "true");
  }, []);

  const handleLogin = () => {
    setIsAuthenticated(true);
    // Clear any cached data from previous sessions
    queryClient.clear();
    // Always redirect to Dashboard after login
    navigate("/");
  };

  const handleLogout = () => {
    localStorage.clear(); // Clear all localStorage including tenantId, userId
    queryClient.clear(); // Clear React Query cache
    setIsAuthenticated(false);
    // Navigate to root (will show login)
    navigate("/");
  };

  if (!isAuthenticated) {
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
