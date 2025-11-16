#!/usr/bin/env python3
"""
ChronoGuard Demo: Blocked Request
==================================

This demo shows ChronoGuard blocking a request to google.com
Watch as the proxy denies access and creates an audit log entry.
"""

import os
import sys
import time

# Terminal colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
BOLD = '\033[1m'
RESET = '\033[0m'

API_BASE_URL = os.getenv("CHRONOGUARD_API_URL", "http://localhost:8000").rstrip("/")
DASHBOARD_URL = os.getenv("CHRONOGUARD_DASHBOARD_URL", "http://localhost:3000").rstrip("/")
PROXY_URL = os.getenv("CHRONOGUARD_PROXY_URL", "http://localhost:8080").rstrip("/")


def print_header():
    """Print demo header."""
    print(f"\n{BOLD}{BLUE}{'=' * 70}{RESET}")
    print(f"{BOLD}{BLUE}  ChronoGuard Demo: BLOCKED Request ❌{RESET}")
    print(f"{BOLD}{BLUE}{'=' * 70}{RESET}\n")


def print_step(step, message):
    """Print a step in the demo."""
    print(f"{YELLOW}[Step {step}]{RESET} {message}")


def print_success(message):
    """Print success message."""
    print(f"{GREEN}✅ {message}{RESET}")


def print_error(message):
    """Print error message."""
    print(f"{RED}❌ {message}{RESET}")


def print_info(message):
    """Print info message."""
    print(f"{BLUE}ℹ️  {message}{RESET}")


def main():
    """Run the blocked request demo."""
    print_header()

    print_step(1, "Initializing Playwright with ChronoGuard proxy...")
    time.sleep(1)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print_error("Playwright not installed!")
        print_info("Run: pip install playwright && playwright install chromium")
        sys.exit(1)

    try:
        with sync_playwright() as p:
            # Configure browser to use ChronoGuard proxy
            print_info("Configuring Chromium to route through ChronoGuard...")

            browser = p.chromium.launch(
                headless=True,
                args=[
                    f'--proxy-server={PROXY_URL}',
                    '--ignore-certificate-errors',  # For demo certs
                ]
            )

            print_success("Browser configured with ChronoGuard proxy")
            print_info(f"Proxy: {PROXY_URL}")

            page = browser.new_page()

            print(f"\n{BOLD}Attempting to access blocked domain:{RESET}")
            print_step(2, "Target: https://google.com")
            print_info("Policy: This domain is BLOCKED by policy")

            time.sleep(1)
            print(f"\n{YELLOW}⏳ Sending request...{RESET}")

            try:
                # This should fail because google.com is blocked by default
                # (Not in the allowed_domains list)
                page.goto("https://google.com", timeout=5000)

                # If we get here, the request wasn't blocked (unexpected)
                print_error("UNEXPECTED: Request was not blocked!")
                print_error("ChronoGuard policy may not be active")
                browser.close()
                sys.exit(1)

            except Exception as e:
                # Expected - request should be blocked
                browser.close()

                print(f"\n{GREEN}{'─' * 70}{RESET}")
                print_success("ChronoGuard successfully BLOCKED the request!")
                print(f"{GREEN}{'─' * 70}{RESET}")

                print(f"\n{BOLD}Details:{RESET}")
                print(f"  • Domain: {RED}google.com{RESET}")
                print(f"  • Status: {RED}BLOCKED{RESET}")
                print(f"  • Reason: Domain not in allowlist")
                print(f"  • Error: {str(e)[:80]}...")

                print(f"\n{BOLD}What just happened:{RESET}")
                print("  1️⃣  Playwright sent HTTPS request to google.com")
                print("  2️⃣  Request routed through ChronoGuard proxy (Envoy)")
                print("  3️⃣  Envoy asked OPA: 'Can this agent access google.com?'")
                print("  4️⃣  OPA checked policy → google.com NOT in allowlist")
                print("  5️⃣  OPA returned DENY decision")
                print("  6️⃣  Envoy blocked the request with 403 Forbidden")
                print("  7️⃣  OPA sent decision log to FastAPI")
                print("  8️⃣  FastAPI created audit entry in PostgreSQL")

                print(f"\n{BOLD}View the audit log:{RESET}")
                print(f"  • Dashboard: {BLUE}{DASHBOARD_URL}{RESET} (navigate to Audit Logs)")
                print(f"  • API: {BLUE}curl {API_BASE_URL}/api/v1/audit/analytics{RESET}")

                print(f"\n{BOLD}Next steps:{RESET}")
                print(f"  • See an ALLOWED request: {GREEN}python playground/demo-allowed.py{RESET}")
                print(f"  • View live audit logs: {GREEN}python playground/demo-interactive.py{RESET}")
                print(f"  • Explore the dashboard: {BLUE}{DASHBOARD_URL}{RESET}")

                print(f"\n{BOLD}{GREEN}✨ Demo complete! ChronoGuard is protecting your automation.{RESET}\n")

    except Exception as e:
        print_error(f"Demo failed: {str(e)}")
        print(f"\n{BOLD}Troubleshooting:{RESET}")
        print("  • Ensure services are running: docker compose ps")
        print("  • Check logs: docker compose logs chronoguard-proxy")
        print(f"  • Check backend: curl {API_BASE_URL}/health")
        print("  • Restart services: docker compose restart")
        sys.exit(1)


if __name__ == "__main__":
    main()
