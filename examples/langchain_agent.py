"""
LangChain Agent Example for ChronoGuard

This example demonstrates how to integrate a LangChain agent with
ChronoGuard's Zero Trust Proxy for secure, auditable AI agent operations.

Prerequisites:
    1. pip install langchain langchain-openai httpx
    2. Generate agent certificates: ./scripts/generate-agent-cert.sh langchain-agent
       Or use demo certs: export CHRONOGUARD_CERT=playground/demo-certs/demo-agent-cert.pem
    3. Ensure ChronoGuard proxy is running on localhost:8080
    4. Register the agent in ChronoGuard dashboard (or use demo-agent-001)
    5. Set OPENAI_API_KEY environment variable

Usage (with generated certs):
    ./scripts/generate-agent-cert.sh langchain-agent
    export CHRONOGUARD_CERT=certs/langchain-agent-cert.pem
    export CHRONOGUARD_KEY=certs/langchain-agent-key.pem
    export CHRONOGUARD_CA=certs/ca-cert.pem
    export OPENAI_API_KEY=your-api-key
    python examples/langchain_agent.py

Usage (with demo certs - for Codespaces/Docker demo):
    export CHRONOGUARD_CERT=playground/demo-certs/demo-agent-cert.pem
    export CHRONOGUARD_KEY=playground/demo-certs/demo-agent-key.pem
    export CHRONOGUARD_CA=playground/demo-certs/ca-cert.pem
    export OPENAI_API_KEY=your-api-key
    python examples/langchain_agent.py

What Gets Routed Through ChronoGuard:
    - OpenAI API calls (via the custom http_client)
    - Custom tool HTTP requests (via the configured requests session)

Note:
    This example demonstrates two patterns:
    1. Simple LLM calls - OpenAI requests go through ChronoGuard
    2. Agent with custom tool - Tool requests also go through ChronoGuard
"""

import logging
import os
import sys
from pathlib import Path

import httpx
import requests


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("chronoguard-langchain")


def _find_cert_path(env_var: str, default_path: str, demo_path: str) -> str:
    """Find certificate path, preferring env var, then demo certs, then default."""
    if os.environ.get(env_var):
        return os.environ[env_var]

    # Check if demo certs exist (for Codespaces/Docker environments)
    if Path(demo_path).exists():
        return demo_path

    return default_path


# Configuration from environment variables with fallback to demo certs
CERT_FILE = _find_cert_path(
    "CHRONOGUARD_CERT",
    "certs/langchain-agent-cert.pem",
    "playground/demo-certs/demo-agent-cert.pem",
)
KEY_FILE = _find_cert_path(
    "CHRONOGUARD_KEY",
    "certs/langchain-agent-key.pem",
    "playground/demo-certs/demo-agent-key.pem",
)
CA_FILE = _find_cert_path(
    "CHRONOGUARD_CA",
    "certs/ca-cert.pem",
    "playground/demo-certs/ca-cert.pem",
)
PROXY_URL = os.environ.get("CHRONOGUARD_PROXY", "https://localhost:8080")


class ChronoGuardTransport(httpx.BaseTransport):
    """Custom transport for ChronoGuard mTLS proxy with self-signed certificates.

    httpx's high-level API doesn't properly expose httpcore's `proxy_ssl_context`
    parameter, which is needed when connecting to an HTTPS proxy with:
    - mTLS client certificates
    - Self-signed server certificates

    This transport wraps httpcore.HTTPProxy directly to configure both:
    1. proxy_ssl_context: For mTLS connection TO the proxy (with client certs, no verify)
    2. ssl_context: For TLS connection through tunnel to TARGET (normal verification)
    """

    def __init__(
        self, proxy_url: str, cert_file: str, key_file: str, verify_target: bool = True
    ) -> None:
        import ssl

        import httpcore

        # SSL context for connecting TO the proxy (mTLS with self-signed cert)
        proxy_ssl_context = ssl.create_default_context()
        proxy_ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        # Disable verification for demo (proxy has self-signed cert)
        proxy_ssl_context.check_hostname = False
        proxy_ssl_context.verify_mode = ssl.CERT_NONE

        # SSL context for connecting through tunnel TO the target (e.g., api.openai.com)
        # Use standard verification for real API endpoints
        if verify_target:
            target_ssl_context = ssl.create_default_context()
        else:
            target_ssl_context = ssl.create_default_context()
            target_ssl_context.check_hostname = False
            target_ssl_context.verify_mode = ssl.CERT_NONE

        # Create httpcore HTTPProxy with BOTH SSL contexts properly configured
        self._pool = httpcore.HTTPProxy(
            proxy_url=proxy_url,
            proxy_ssl_context=proxy_ssl_context,
            ssl_context=target_ssl_context,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Forward request through the proxy pool."""
        import httpcore

        # Convert httpx.Request to httpcore format
        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )

        # Make the request through the proxy
        resp = self._pool.handle_request(req)

        # Read the response content and create a proper httpx.Response
        # httpcore returns an iterable stream, we need to read it for httpx
        content = b"".join(resp.stream)

        return httpx.Response(
            status_code=resp.status,
            headers=resp.headers,
            content=content,
            extensions=resp.extensions,
        )

    def close(self) -> None:
        """Close the connection pool."""
        self._pool.close()

    def __enter__(self) -> "ChronoGuardTransport":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def create_chronoguard_http_client() -> httpx.Client:
    """Create an httpx client configured for ChronoGuard mTLS proxy.

    This uses a custom transport to properly handle:
    1. mTLS connection to the proxy (with client certificates)
    2. Self-signed proxy certificates (verification disabled for demo)
    3. Standard TLS verification for target APIs (e.g., OpenAI)

    In production, use properly signed certificates for the proxy.
    """
    transport = ChronoGuardTransport(
        proxy_url=PROXY_URL,
        cert_file=CERT_FILE,
        key_file=KEY_FILE,
        verify_target=True,  # Verify real API endpoints like OpenAI
    )

    return httpx.Client(
        transport=transport,
        timeout=60.0,
    )


def create_chronoguard_requests_session() -> requests.Session:
    """Create a requests session configured for ChronoGuard mTLS proxy."""
    session = requests.Session()
    session.cert = (CERT_FILE, KEY_FILE)
    session.verify = CA_FILE
    session.proxies = {
        "http": PROXY_URL,
        "https": PROXY_URL,
    }
    return session


def verify_certificates() -> bool:
    """Verify that all required certificate files exist."""
    files = [
        (CERT_FILE, "Certificate"),
        (KEY_FILE, "Key"),
        (CA_FILE, "CA"),
    ]

    all_exist = True
    for filepath, name in files:
        if not os.path.exists(filepath):
            logger.error(f"{name} file not found: {filepath}")
            all_exist = False

    if not all_exist:
        logger.error("Run: ./scripts/generate-agent-cert.sh langchain-agent")

    return all_exist


def run_agent_with_custom_tool() -> None:
    """Run a LangChain agent with a custom tool that routes through ChronoGuard."""
    try:
        from langchain.agents import AgentType, initialize_agent
        from langchain.tools import Tool
        from langchain_openai import ChatOpenAI
    except ImportError:
        logger.error("LangChain not installed. Run: pip install langchain langchain-openai")
        sys.exit(1)

    if not os.environ.get("OPENAI_API_KEY"):
        logger.error("OPENAI_API_KEY environment variable not set")
        sys.exit(1)

    logger.info("Initializing LangChain agent with ChronoGuard proxy...")

    # Create HTTP clients for ChronoGuard using context managers to avoid resource leaks
    with create_chronoguard_http_client() as http_client, \
         create_chronoguard_requests_session() as requests_session:

        # Initialize ChatOpenAI with custom HTTP client
        # All OpenAI API calls will go through ChronoGuard
        llm = ChatOpenAI(
            model="gpt-3.5-turbo",
            temperature=0,
            http_client=http_client,
        )

        # Create a custom HTTP fetch tool that uses our proxied session
        def fetch_url(url: str) -> str:
            """Fetch a URL through ChronoGuard proxy."""
            try:
                response = requests_session.get(url, timeout=30)
                return f"Status: {response.status_code}\nContent: {response.text[:500]}"
            except requests.exceptions.RequestException as e:
                return f"Error fetching {url}: {e}"

        # Define the tool
        fetch_tool = Tool(
            name="fetch_url",
            description="Fetch content from a URL. All requests are audited by ChronoGuard.",
            func=fetch_url,
        )

        # Initialize the agent with our custom tool
        agent = initialize_agent(
            [fetch_tool],
            llm,
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
            verbose=True,
        )

        # Run a sample query
        logger.info("Running agent query...")
        result = agent.run(
            "What is my current IP address? "
            "Use the fetch_url tool to get https://httpbin.org/ip"
        )

        logger.info(f"Agent result: {result}")
        logger.info("Check ChronoGuard dashboard for audit trail of all HTTP requests.")


def run_simple_llm_call() -> None:
    """Run a simple LLM call through ChronoGuard (no tools)."""
    try:
        from langchain_openai import ChatOpenAI
    except ImportError:
        logger.error("LangChain not installed. Run: pip install langchain langchain-openai")
        sys.exit(1)

    if not os.environ.get("OPENAI_API_KEY"):
        logger.error("OPENAI_API_KEY environment variable not set")
        sys.exit(1)

    logger.info("Making simple LLM call through ChronoGuard proxy...")

    # Create custom HTTP client for ChronoGuard using context manager to avoid resource leaks
    with create_chronoguard_http_client() as http_client:
        # Initialize ChatOpenAI with custom HTTP client
        llm = ChatOpenAI(
            model="gpt-3.5-turbo",
            temperature=0,
            http_client=http_client,
        )

        # Make a simple call
        response = llm.invoke("What is 2 + 2? Answer in one word.")

        logger.info(f"LLM Response: {response.content}")
        logger.info("Check ChronoGuard dashboard - you should see the OpenAI API call.")


def main() -> None:
    """Main entry point."""
    logger.info("ChronoGuard LangChain Agent Example")
    logger.info(f"Proxy: {PROXY_URL}")
    logger.info(f"Certificate: {CERT_FILE}")

    # Verify certificates
    if not verify_certificates():
        sys.exit(1)

    # Run examples
    logger.info("=" * 60)
    logger.info("Example 1: Simple LLM Call (OpenAI via ChronoGuard)")
    logger.info("=" * 60)
    run_simple_llm_call()

    logger.info("")
    logger.info("=" * 60)
    logger.info("Example 2: Agent with Custom Tool (All requests via ChronoGuard)")
    logger.info("=" * 60)
    run_agent_with_custom_tool()

    logger.info("")
    logger.info("=" * 60)
    logger.info("All examples completed!")
    logger.info("Check ChronoGuard dashboard for complete audit trail.")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
