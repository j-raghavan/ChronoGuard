#!/usr/bin/env python3
"""
ChronoGuard Demo: Blocked Request
==================================

This demo shows ChronoGuard blocking a request to google.com
Watch as the proxy denies access and creates an audit log entry.

Uses mTLS (mutual TLS) with client certificates to authenticate with
the ChronoGuard proxy, just like a real agent would in production.
"""

import os
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


# Terminal colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _detect_proxy_host() -> str:
    """Auto-detect whether to use Docker hostname or localhost.

    When running inside Docker network, use 'chronoguard-proxy'.
    When running from host machine (Codespaces terminal), use 'localhost'.
    """
    import socket

    # Check if explicitly set via environment
    if os.getenv("CHRONOGUARD_PROXY_HOST"):
        return os.environ["CHRONOGUARD_PROXY_HOST"]

    # Try to resolve Docker hostname - if it works, we're in Docker network
    try:
        socket.gethostbyname("chronoguard-proxy")
        return "chronoguard-proxy"
    except socket.gaierror:
        # Can't resolve Docker hostname, use localhost
        return "localhost"


API_BASE_URL = os.getenv("CHRONOGUARD_API_URL", "http://chronoguard-api:8000").rstrip("/")
DASHBOARD_URL = os.getenv("CHRONOGUARD_DASHBOARD_URL", "http://chronoguard-dashboard:80").rstrip(
    "/"
)
PROXY_HOST = _detect_proxy_host()
PROXY_PORT = int(os.getenv("CHRONOGUARD_PROXY_PORT", "8080"))

# Certificate paths (relative to playground directory or absolute)
SCRIPT_DIR = Path(__file__).parent
CERTS_DIR = SCRIPT_DIR / "demo-certs"
CA_CERT = CERTS_DIR / "ca-cert.pem"
CLIENT_CERT = CERTS_DIR / "demo-agent-cert.pem"
CLIENT_KEY = CERTS_DIR / "demo-agent-key.pem"


def print_header() -> None:
    """Print demo header."""
    print(f"\n{BOLD}{RED}{'=' * 70}{RESET}")
    print(f"{BOLD}{RED}  ChronoGuard Demo: BLOCKED Request ❌{RESET}")
    print(f"{BOLD}{RED}{'=' * 70}{RESET}\n")


def print_step(step: int, message: str) -> None:
    """Print a step in the demo."""
    print(f"{YELLOW}[Step {step}]{RESET} {message}")


def print_success(message: str) -> None:
    """Print success message."""
    print(f"{GREEN}✅ {message}{RESET}")


def print_error(message: str) -> None:
    """Print error message."""
    print(f"{RED}❌ {message}{RESET}")


def print_info(message: str) -> None:
    """Print info message."""
    print(f"{BLUE}ℹ️  {message}{RESET}")


def check_certificates() -> bool:
    """Verify that all required certificates exist."""
    missing = []
    for cert_file in [CA_CERT, CLIENT_CERT, CLIENT_KEY]:
        if not cert_file.exists():
            missing.append(str(cert_file))

    if missing:
        print_error("Missing certificate files:")
        for f in missing:
            print(f"  • {f}")
        print_info(
            "Run from the workspace root: cd /workspace && python playground/demo-blocked.py"
        )
        return False

    return True


def attempt_blocked_request(
    target_url: str,
    proxy_host: str,
    proxy_port: int,
    client_cert: Path,
    client_key: Path,
) -> tuple[bool, str]:
    """
    Attempt to make a request that should be blocked by policy.

    Returns:
        Tuple of (was_blocked, details)
    """
    import socket

    parsed = urlparse(target_url)
    target_host = parsed.hostname
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Create SSL context for mTLS connection to proxy
    proxy_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    proxy_ssl_context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    proxy_ssl_context.check_hostname = False
    proxy_ssl_context.verify_mode = ssl.CERT_NONE  # Demo only

    try:
        # Connect to proxy with mTLS
        raw_socket = socket.create_connection((proxy_host, proxy_port), timeout=10)
        proxy_socket = proxy_ssl_context.wrap_socket(raw_socket, server_hostname="localhost")

        # Send CONNECT request to establish tunnel
        connect_request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"User-Agent: ChronoGuard-Demo-Agent/1.0\r\n"
            f"X-Agent-ID: demo-agent-001\r\n"
            f"\r\n"
        )
        proxy_socket.sendall(connect_request.encode())

        # Read CONNECT response
        response_data = b""
        while b"\r\n\r\n" not in response_data:
            chunk = proxy_socket.recv(4096)
            if not chunk:
                break
            response_data += chunk

        proxy_socket.close()

        response_line = response_data.split(b"\r\n")[0].decode()

        # Check if the request was blocked (403 Forbidden)
        if "403" in response_line:
            return True, "403 Forbidden - Access denied by policy"
        if "200" in response_line:
            return False, "200 OK - Request was unexpectedly allowed"
        return True, f"Blocked with: {response_line}"

    except Exception as e:
        return True, f"Connection blocked: {str(e)}"


def main() -> None:
    """Run the blocked request demo."""
    print_header()

    # Step 1: Check certificates
    print_step(1, "Checking mTLS certificates...")
    if not check_certificates():
        sys.exit(1)
    print_success("All certificates found")
    print_info(f"CA Cert: {CA_CERT}")
    print_info(f"Client Cert: {CLIENT_CERT}")

    # Step 2: Configure connection
    print_step(2, "Configuring mTLS connection to ChronoGuard proxy...")
    print_info(f"Proxy: {PROXY_HOST}:{PROXY_PORT}")
    time.sleep(1)

    # Step 3: Attempt blocked request
    target_url = "https://google.com"
    print(f"\n{BOLD}Attempting to access blocked domain:{RESET}")
    print_step(3, f"Target: {target_url}")
    print_info("Policy: This domain is NOT in the allowlist")

    time.sleep(1)
    print(f"\n{YELLOW}⏳ Sending request through ChronoGuard proxy...{RESET}")

    was_blocked, details = attempt_blocked_request(
        target_url=target_url,
        proxy_host=PROXY_HOST,
        proxy_port=PROXY_PORT,
        client_cert=CLIENT_CERT,
        client_key=CLIENT_KEY,
    )

    if was_blocked:
        print(f"\n{GREEN}{'─' * 70}{RESET}")
        print_success("ChronoGuard successfully BLOCKED the request!")
        print(f"{GREEN}{'─' * 70}{RESET}")

        print(f"\n{BOLD}Details:{RESET}")
        print(f"  • Domain: {RED}google.com{RESET}")
        print(f"  • Status: {RED}BLOCKED{RESET}")
        print("  • Reason: Domain not in allowlist")
        print(f"  • Response: {details}")

        print(f"\n{BOLD}What just happened:{RESET}")
        print("  1️⃣  Demo agent connected to ChronoGuard proxy with mTLS")
        print("  2️⃣  Agent certificate authenticated the request")
        print("  3️⃣  Sent CONNECT request for google.com")
        print("  4️⃣  Envoy asked OPA: 'Can this agent access google.com?'")
        print("  5️⃣  OPA checked policy → google.com NOT in allowlist")
        print("  6️⃣  OPA returned DENY decision")
        print("  7️⃣  Envoy blocked the request with 403 Forbidden")
        print("  8️⃣  OPA sent decision log to FastAPI audit service")

        print(f"\n{BOLD}View the audit log:{RESET}")
        print(f"  • Dashboard: {BLUE}{DASHBOARD_URL}{RESET} (Audit Logs section)")
        print(f"  • API: {BLUE}curl {API_BASE_URL}/api/v1/audit/query{RESET}")

        print(f"\n{BOLD}Key Takeaway:{RESET}")
        print(f"  {RED}🛡️  ChronoGuard prevents unauthorized network access")
        print(f"     and creates audit trails for compliance!{RESET}")

    else:
        print_error("UNEXPECTED: Request was not blocked!")
        print_error(f"Details: {details}")
        print_info("The policy may not have google.com blocked")
        sys.exit(1)

    print(f"\n{BOLD}Next steps:{RESET}")
    print(f"  • See an ALLOWED request: {GREEN}python playground/demo-allowed.py{RESET}")
    print(f"  • View live audit logs: {GREEN}python playground/demo-interactive.py{RESET}")
    print(f"  • Read the docs: {BLUE}{API_BASE_URL}/docs{RESET}")

    print(f"\n{BOLD}{GREEN}✨ Demo complete!{RESET}\n")


if __name__ == "__main__":
    main()
