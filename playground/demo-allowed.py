#!/usr/bin/env python3
"""
ChronoGuard Demo: Allowed Request
==================================

This demo shows ChronoGuard allowing a request to an approved domain.
Watch as the proxy permits access and logs the activity.
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
    print(f"\n{BOLD}{GREEN}{'=' * 70}{RESET}")
    print(f"{BOLD}{GREEN}  ChronoGuard Demo: ALLOWED Request ✅{RESET}")
    print(f"{BOLD}{GREEN}{'=' * 70}{RESET}\n")


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
    """Run the allowed request demo."""
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
                    '--ignore-certificate-errors',
                ]
            )

            print_success("Browser configured with ChronoGuard proxy")
            print_info(f"Proxy: {PROXY_URL}")

            page = browser.new_page()

            print(f"\n{BOLD}Attempting to access allowed domain:{RESET}")
            print_step(2, "Target: https://example.com")
            print_info("Policy: This domain is ALLOWED by policy")

            time.sleep(1)
            print(f"\n{YELLOW}⏳ Sending request...{RESET}")

            try:
                # This should succeed because example.com is in allowed_domains
                response = page.goto("https://example.com", timeout=10000, wait_until="domcontentloaded")

                if response and response.ok:
                    print(f"\n{GREEN}{'─' * 70}{RESET}")
                    print_success("ChronoGuard successfully ALLOWED the request!")
                    print(f"{GREEN}{'─' * 70}{RESET}")

                    print(f"\n{BOLD}Details:{RESET}")
                    print(f"  • Domain: {GREEN}example.com{RESET}")
                    print(f"  • Status: {GREEN}ALLOWED{RESET} ({response.status})")
                    print(f"  • Reason: Domain in allowlist")
                    print(f"  • Title: {page.title()[:50]}")

                    browser.close()

                    print(f"\n{BOLD}What just happened:{RESET}")
                    print("  1️⃣  Playwright sent HTTPS request to example.com")
                    print("  2️⃣  Request routed through ChronoGuard proxy (Envoy)")
                    print("  3️⃣  Envoy asked OPA: 'Can this agent access example.com?'")
                    print("  4️⃣  OPA checked policy → example.com IS in allowlist")
                    print("  5️⃣  OPA returned ALLOW decision")
                    print("  6️⃣  Envoy forwarded request to example.com")
                    print("  7️⃣  Page loaded successfully")
                    print("  8️⃣  OPA sent decision log to FastAPI")
                    print("  9️⃣  FastAPI created audit entry with timestamp")

                    print(f"\n{BOLD}View the audit log:{RESET}")
                    print(f"  • Dashboard: {BLUE}{DASHBOARD_URL}{RESET} (Audit Logs section)")
                    print(f"  • API: {BLUE}curl {API_BASE_URL}/api/v1/audit/analytics{RESET}")

                    print(f"\n{BOLD}Key Takeaway:{RESET}")
                    print(f"  {GREEN}✨ ChronoGuard creates cryptographic proof of when/where your")
                    print(f"     automation accessed the internet - perfect for compliance!{RESET}")

                else:
                    print_error(f"Request failed with status: {response.status if response else 'unknown'}")
                    browser.close()
                    sys.exit(1)

            except Exception as e:
                print_error(f"Request failed: {str(e)}")
                print_info("This domain may be blocked by policy")
                browser.close()
                sys.exit(1)

            print(f"\n{BOLD}Next steps:{RESET}")
            print(f"  • See a BLOCKED request: {RED}python playground/demo-blocked.py{RESET}")
            print(f"  • View live audit logs: {GREEN}python playground/demo-interactive.py{RESET}")
            print(f"  • Read the docs: {BLUE}{API_BASE_URL}/docs{RESET}")

            print(f"\n{BOLD}{GREEN}✨ Demo complete!{RESET}\n")

    except Exception as e:
        print_error(f"Demo failed: {str(e)}")
        print(f"\n{BOLD}Troubleshooting:{RESET}")
        print("  • Ensure services are running: docker compose ps")
        print("  • Check proxy logs: docker compose logs chronoguard-proxy")
        print(f"  • Check backend: curl {API_BASE_URL}/health")
        sys.exit(1)


if __name__ == "__main__":
    main()
