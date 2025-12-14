"""
Generic Python Agent Example for ChronoGuard

This example demonstrates how to connect any Python application
to ChronoGuard's Zero Trust Proxy using mTLS authentication.

Prerequisites:
    1. Generate agent certificates: ./scripts/generate-agent-cert.sh my-python-agent
    2. Ensure ChronoGuard proxy is running on localhost:8080
    3. Register the agent in ChronoGuard dashboard

Usage:
    export CHRONOGUARD_CERT=certs/my-python-agent-cert.pem
    export CHRONOGUARD_KEY=certs/my-python-agent-key.pem
    export CHRONOGUARD_CA=certs/ca-cert.pem
    export CHRONOGUARD_PROXY=https://localhost:8080
    python generic_python_agent.py
"""

import logging
import os
import sys

import requests


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("chronoguard-agent")

# Configuration from environment variables
CERT_FILE = os.environ.get("CHRONOGUARD_CERT", "certs/my-python-agent-cert.pem")
KEY_FILE = os.environ.get("CHRONOGUARD_KEY", "certs/my-python-agent-key.pem")
CA_FILE = os.environ.get("CHRONOGUARD_CA", "certs/ca-cert.pem")
PROXY_URL = os.environ.get("CHRONOGUARD_PROXY", "https://localhost:8080")


def create_session() -> requests.Session:
    """Create a requests session configured for ChronoGuard mTLS proxy."""
    session = requests.Session()

    # Configure mTLS client certificate
    session.cert = (CERT_FILE, KEY_FILE)

    # Configure proxy for all requests
    session.proxies = {
        "http": PROXY_URL,
        "https": PROXY_URL,
    }

    # SECURITY: Always verify the proxy's certificate in production.
    # Use the CA certificate that signed the proxy's certificate.
    # WARNING: Never use verify=False in production environments.
    session.verify = CA_FILE

    return session


def make_request(session: requests.Session, url: str) -> None:
    """Make a request through the ChronoGuard proxy."""
    logger.info(f"Requesting: {url}")

    try:
        response = session.get(url, timeout=30)
        logger.info(f"Status: {response.status_code}")
        logger.info(f"Response: {response.text[:200]}...")
    except requests.exceptions.SSLError as e:
        logger.error(f"SSL/TLS error - check certificates: {e}")
        sys.exit(1)
    except requests.exceptions.ProxyError as e:
        logger.error(f"Proxy error - is ChronoGuard running? {e}")
        sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection failed: {e}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        logger.error("Request timed out")
        sys.exit(1)


def main() -> None:
    """Main entry point demonstrating mTLS proxy connection."""
    logger.info("ChronoGuard Generic Python Agent Example")
    logger.info(f"Proxy: {PROXY_URL}")
    logger.info(f"Certificate: {CERT_FILE}")

    # Verify certificate files exist
    for filepath, name in [
        (CERT_FILE, "Certificate"),
        (KEY_FILE, "Key"),
        (CA_FILE, "CA"),
    ]:
        if not os.path.exists(filepath):
            logger.error(f"{name} file not found: {filepath}")
            logger.error("Run: ./scripts/generate-agent-cert.sh my-python-agent")
            sys.exit(1)

    # Create configured session
    session = create_session()

    # Example requests - these will be audited by ChronoGuard
    test_urls = [
        "https://httpbin.org/ip",
        "https://httpbin.org/headers",
        "https://api.github.com/zen",
    ]

    for url in test_urls:
        make_request(session, url)
        logger.info("-" * 50)

    logger.info("All requests completed. Check ChronoGuard dashboard for audit logs.")


if __name__ == "__main__":
    main()
