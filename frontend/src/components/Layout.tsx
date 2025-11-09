import type { ReactNode } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { Activity, Shield, FileText, BarChart3, Bell, Search, LogOut } from "lucide-react";

interface LayoutProps {
  children?: ReactNode;
  onLogout?: () => void;
}

export function Layout({ children, onLogout }: LayoutProps) {
  const location = useLocation();

  const navigation = [
    { name: "Dashboard", href: "/", icon: BarChart3 },
    { name: "Agents", href: "/agents", icon: Shield },
    { name: "Policies", href: "/policies", icon: FileText },
    { name: "Audit Log", href: "/audit", icon: Activity },
  ];

  const isActive = (href: string) => {
    if (href === "/") {
      return location.pathname === "/";
    }
    return location.pathname.startsWith(href);
  };

  return (
    <div style={{ minHeight: "100vh", backgroundColor: "hsl(var(--background))" }}>
      {/* Sidebar */}
      <aside style={{
        position: "fixed",
        top: 0,
        left: 0,
        bottom: 0,
        width: "16rem",
        backgroundColor: "white",
        borderRight: "1px solid hsl(var(--border))",
        zIndex: 50,
        display: "flex",
        flexDirection: "column"
      }}>
        {/* Logo Section */}
        <div style={{
          display: "flex",
          height: "5rem",
          alignItems: "center",
          padding: "0 1.5rem",
          borderBottom: "1px solid hsl(var(--border))"
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <img
              src="/assets/icons/chronoguard_icon_64.png"
              alt="ChronoGuard Logo"
              style={{ width: "2.5rem", height: "2.5rem" }}
            />
            <div>
              <h1 style={{ fontSize: "1.125rem", fontWeight: "bold", color: "hsl(var(--foreground))" }}>
                ChronoGuard
              </h1>
              <p style={{ fontSize: "0.75rem", color: "hsl(var(--muted-foreground))" }}>
                Time-Based Access Control
              </p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav style={{ padding: "1rem", display: "flex", flexDirection: "column", gap: "0.25rem", flex: 1 }}>
          {navigation.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.href);
            return (
              <Link
                key={item.name}
                to={item.href}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "0.75rem 1rem",
                  borderRadius: "0.5rem",
                  transition: "all 0.2s ease",
                  color: active ? "#42CDF8" : "hsl(var(--muted-foreground))",
                  backgroundColor: active ? "hsl(var(--accent))" : "transparent",
                  fontWeight: active ? 500 : 400,
                  textDecoration: "none"
                }}
              >
                <span style={{ fontWeight: 500 }}>{item.name}</span>
                <Icon style={{ height: "1rem", width: "1rem" }} />
              </Link>
            );
          })}
        </nav>

        {/* Sidebar Footer */}
        <div style={{
          position: "absolute",
          bottom: 0,
          left: 0,
          right: 0,
          padding: "1rem",
          borderTop: "1px solid hsl(var(--border))"
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", padding: "0.75rem 0.75rem" }}>
            <div
              style={{
                width: "2.5rem",
                height: "2.5rem",
                borderRadius: "50%",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: "linear-gradient(135deg, #22D3EE 0%, #38BDF8 100%)",
                color: "white"
              }}
            >
              <span style={{ color: "white", fontWeight: 600, fontSize: "0.875rem" }}>AD</span>
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <p style={{ fontSize: "0.875rem", fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "hsl(var(--foreground))" }}>
                Admin User
              </p>
              <p style={{ fontSize: "0.75rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "hsl(var(--muted-foreground))" }}>
                System Administrator
              </p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main style={{ paddingLeft: "16rem" }}>
        {/* Top Header */}
        <header style={{
          height: "5rem",
          backgroundColor: "white",
          borderBottom: "1px solid hsl(var(--border))",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 2rem",
          position: "sticky",
          top: 0,
          zIndex: 40
        }}>
          <div style={{ flex: 1, maxWidth: "36rem" }}>
            <div style={{ position: "relative" }}>
              <Search style={{
                position: "absolute",
                left: "0.75rem",
                top: "50%",
                transform: "translateY(-50%)",
                height: "1rem",
                width: "1rem",
                color: "hsl(var(--muted-foreground))"
              }} />
              <input
                type="text"
                placeholder="Search..."
                style={{
                  width: "100%",
                  paddingLeft: "2.5rem",
                  paddingRight: "1rem",
                  paddingTop: "0.625rem",
                  paddingBottom: "0.625rem",
                  borderRadius: "0.5rem",
                  border: "1px solid hsl(var(--border))",
                  backgroundColor: "hsl(var(--background))",
                  fontSize: "0.875rem",
                  outline: "none"
                }}
              />
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
            <button
              style={{
                position: "relative",
                padding: "0.5rem",
                borderRadius: "0.5rem",
                color: "hsl(var(--muted-foreground))",
                backgroundColor: "transparent",
                border: "none",
                cursor: "pointer"
              }}
            >
              <Bell style={{ height: "1.25rem", width: "1.25rem" }} />
              <span style={{
                position: "absolute",
                top: "0.375rem",
                right: "0.375rem",
                width: "0.5rem",
                height: "0.5rem",
                borderRadius: "50%",
                backgroundColor: "hsl(var(--danger))"
              }}></span>
            </button>
            {onLogout && (
              <button
                onClick={onLogout}
                title="Logout"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  padding: "0.5rem 1rem",
                  borderRadius: "0.5rem",
                  color: "#EF4444",
                  backgroundColor: "transparent",
                  border: "1px solid #EF4444",
                  cursor: "pointer",
                  fontSize: "0.875rem",
                  fontWeight: 500,
                  transition: "all 0.2s"
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = "#EF4444";
                  e.currentTarget.style.color = "white";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = "transparent";
                  e.currentTarget.style.color = "#EF4444";
                }}
              >
                <LogOut style={{ height: "1rem", width: "1rem" }} />
                Logout
              </button>
            )}
          </div>
        </header>

        {/* Page Content */}
        <div style={{ padding: "2rem" }}>
          {children || <Outlet />}
        </div>
      </main>
    </div>
  );
}
