#!/usr/bin/env python3
"""
ChronoGuard Demo: Allowed Request
==================================

This demo shows ChronoGuard allowing a request to an approved domain.
Watch as the proxy permits access and logs the activity.

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
    print(f"\n{BOLD}{GREEN}{'=' * 70}{RESET}")
    print(f"{BOLD}{GREEN}  ChronoGuard Demo: ALLOWED Request ✅{RESET}")
    print(f"{BOLD}{GREEN}{'=' * 70}{RESET}\n")


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
            "Run from the workspace root: cd /workspace && python playground/demo-allowed.py"
        )
        return False

    return True


def make_https_request_via_proxy(
    target_url: str,
    proxy_host: str,
    proxy_port: int,
    ca_cert: Path,
    client_cert: Path,
    client_key: Path,
) -> tuple[int, str, dict]:
    """
    Make an HTTPS request through the mTLS proxy using CONNECT tunnel.

    Args:
        target_url: The URL to fetch (e.g., https://example.com)
        proxy_host: ChronoGuard proxy hostname
        proxy_port: ChronoGuard proxy port
        ca_cert: Path to CA certificate for verifying proxy
        client_cert: Path to client certificate for mTLS
        client_key: Path to client private key for mTLS

    Returns:
        Tuple of (status_code, body, headers)
    """
    import socket

    parsed = urlparse(target_url)
    target_host = parsed.hostname
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Create SSL context for mTLS connection to proxy
    # Note: For demo purposes, we don't verify the server cert since the demo certs
    # are self-signed. In production, you would use properly signed certificates.
    proxy_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    proxy_ssl_context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    proxy_ssl_context.check_hostname = False
    proxy_ssl_context.verify_mode = ssl.CERT_NONE  # Demo only - verify in production!

    # Connect to proxy with mTLS
    raw_socket = socket.create_connection((proxy_host, proxy_port), timeout=30)
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

    response_line = response_data.split(b"\r\n")[0].decode()
    if "200" not in response_line:
        proxy_socket.close()
        raise ConnectionError(f"Proxy CONNECT failed: {response_line}")

    # The CONNECT tunnel is now established through the mTLS connection.
    # For HTTPS targets, we need TLS-in-TLS (TLS to target inside mTLS tunnel to proxy).
    # Use MemoryBIO for proper TLS layering over the existing SSL socket.
    target_ssl_context = ssl.create_default_context()

    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    target_ssl = target_ssl_context.wrap_bio(incoming, outgoing, server_hostname=target_host)

    # Perform TLS handshake with target through the tunnel
    def do_ssl_io() -> None:
        """Flush outgoing and read incoming SSL data through the tunnel."""
        # Send any pending outgoing data
        out_data = outgoing.read()
        if out_data:
            proxy_socket.sendall(out_data)

    # Initial handshake
    while True:
        try:
            target_ssl.do_handshake()
            do_ssl_io()
            break
        except ssl.SSLWantReadError:
            do_ssl_io()
            chunk = proxy_socket.recv(16384)
            if not chunk:
                raise ConnectionError("Connection closed during TLS handshake") from None
            incoming.write(chunk)
        except ssl.SSLWantWriteError:
            do_ssl_io()

    # Build and send HTTP request through the TLS tunnel
    http_request = (
        f"GET {parsed.path or '/'} HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"User-Agent: ChronoGuard-Demo-Agent/1.0\r\n"
        f"Accept: text/html,*/*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    # Write request to TLS layer
    target_ssl.write(http_request.encode())
    do_ssl_io()

    # Read response from TLS tunnel
    response = b""
    while True:
        try:
            chunk = target_ssl.read(16384)
            if chunk:
                response += chunk
            else:
                break
        except ssl.SSLWantReadError:
            try:
                encrypted = proxy_socket.recv(16384)
                if not encrypted:
                    break
                incoming.write(encrypted)
            except (socket.timeout, OSError):
                break
        except ssl.SSLZeroReturnError:
            break
        except ssl.SSLError:
            break

    proxy_socket.close()

    # Parse HTTP response
    if not response:
        raise ConnectionError("No response received from target")

    header_end = response.find(b"\r\n\r\n")
    if header_end == -1:
        raise ConnectionError(f"Invalid HTTP response: {response[:100]}")

    header_section = response[:header_end].decode("utf-8", errors="replace")
    body = response[header_end + 4 :].decode("utf-8", errors="replace")

    # Parse status code
    status_line = header_section.split("\r\n")[0]
    status_code = int(status_line.split()[1])

    # Parse headers
    headers = {}
    for line in header_section.split("\r\n")[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key.lower()] = value

    return status_code, body, headers


def main() -> None:
    """Run the allowed request demo."""
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

    # Step 3: Make the request
    target_url = "https://example.com"
    print(f"\n{BOLD}Attempting to access allowed domain:{RESET}")
    print_step(3, f"Target: {target_url}")
    print_info("Policy: This domain is ALLOWED by policy")

    time.sleep(1)
    print(f"\n{YELLOW}⏳ Sending request through ChronoGuard proxy...{RESET}")

    try:
        status_code, body, headers = make_https_request_via_proxy(
            target_url=target_url,
            proxy_host=PROXY_HOST,
            proxy_port=PROXY_PORT,
            ca_cert=CA_CERT,
            client_cert=CLIENT_CERT,
            client_key=CLIENT_KEY,
        )

        if 200 <= status_code < 400:
            print(f"\n{GREEN}{'─' * 70}{RESET}")
            print_success("ChronoGuard successfully ALLOWED the request!")
            print(f"{GREEN}{'─' * 70}{RESET}")

            # Extract title from HTML
            title = "Example Domain"
            if "<title>" in body:
                start = body.find("<title>") + 7
                end = body.find("</title>")
                title = body[start:end]

            print(f"\n{BOLD}Details:{RESET}")
            print(f"  • Domain: {GREEN}example.com{RESET}")
            print(f"  • Status: {GREEN}ALLOWED{RESET} ({status_code})")
            print("  • Reason: Domain in allowlist")
            print(f"  • Title: {title}")
            print(f"  • Content-Length: {headers.get('content-length', 'unknown')} bytes")

            print(f"\n{BOLD}What just happened:{RESET}")
            print("  1️⃣  Demo agent connected to ChronoGuard proxy with mTLS")
            print("  2️⃣  Agent certificate authenticated the request")
            print("  3️⃣  Sent CONNECT request to establish HTTPS tunnel")
            print("  4️⃣  Envoy asked OPA: 'Can this agent access example.com?'")
            print("  5️⃣  OPA checked policy → example.com IS in allowlist")
            print("  6️⃣  OPA returned ALLOW decision")
            print("  7️⃣  Envoy forwarded request through tunnel")
            print("  8️⃣  Page content returned successfully")
            print("  9️⃣  OPA sent decision log to FastAPI audit service")

            print(f"\n{BOLD}View the audit log:{RESET}")
            print(f"  • Dashboard: {BLUE}{DASHBOARD_URL}{RESET} (Audit Logs section)")
            print(f"  • API: {BLUE}curl {API_BASE_URL}/api/v1/audit/query{RESET}")

            print(f"\n{BOLD}Key Takeaway:{RESET}")
            print(f"  {GREEN}✨ ChronoGuard creates cryptographic proof of when/where your")
            print(f"     automation accessed the internet - perfect for compliance!{RESET}")

        else:
            print_error(f"Request returned status: {status_code}")
            sys.exit(1)

    except ConnectionError as e:
        print_error(f"Connection failed: {e}")
        print_info("The request may have been blocked by OPA policy")
        print(f"\n{BOLD}Check the logs:{RESET}")
        print("  • OPA: docker logs chronoguard-policy-engine --tail 20")
        print("  • Proxy: docker logs chronoguard-proxy --tail 20")
        sys.exit(1)
    except Exception as e:
        print_error(f"Request failed: {e}")
        print(f"\n{BOLD}Troubleshooting:{RESET}")
        print("  • Ensure services are running: docker compose ps")
        print("  • Check proxy logs: docker logs chronoguard-proxy --tail 20")
        print(f"  • Check backend: curl {API_BASE_URL}/health")
        sys.exit(1)

    print(f"\n{BOLD}Next steps:{RESET}")
    print(f"  • See a BLOCKED request: {RED}python playground/demo-blocked.py{RESET}")
    print(f"  • View live audit logs: {GREEN}python playground/demo-interactive.py{RESET}")
    print(f"  • Read the docs: {BLUE}{API_BASE_URL}/docs{RESET}")

    print(f"\n{BOLD}{GREEN}✨ Demo complete!{RESET}\n")


if __name__ == "__main__":
    main()
