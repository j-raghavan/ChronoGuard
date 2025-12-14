"""
LangChain Agent Example for ChronoGuard

This example demonstrates how to integrate a LangChain agent with
ChronoGuard's Zero Trust Proxy for secure, auditable AI agent operations.

Prerequisites:
    1. pip install langchain langchain-openai httpx
    2. Generate agent certificates: ./scripts/generate-agent-cert.sh langchain-agent
    3. Ensure ChronoGuard proxy is running on localhost:8080
    4. Register the agent in ChronoGuard dashboard
    5. Set OPENAI_API_KEY environment variable

Usage:
    export CHRONOGUARD_CERT=certs/langchain-agent-cert.pem
    export CHRONOGUARD_KEY=certs/langchain-agent-key.pem
    export CHRONOGUARD_CA=certs/ca-cert.pem
    export CHRONOGUARD_PROXY=https://localhost:8080
    export OPENAI_API_KEY=your-api-key
    python langchain_agent.py

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
import ssl
import sys

import httpx
import requests


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("chronoguard-langchain")

# Configuration from environment variables
CERT_FILE = os.environ.get("CHRONOGUARD_CERT", "certs/langchain-agent-cert.pem")
KEY_FILE = os.environ.get("CHRONOGUARD_KEY", "certs/langchain-agent-key.pem")
CA_FILE = os.environ.get("CHRONOGUARD_CA", "certs/ca-cert.pem")
PROXY_URL = os.environ.get("CHRONOGUARD_PROXY", "https://localhost:8080")


def create_chronoguard_http_client() -> httpx.Client:
    """Create an httpx client configured for ChronoGuard mTLS proxy."""
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    ssl_context.load_verify_locations(cafile=CA_FILE)

    return httpx.Client(
        proxy=PROXY_URL,
        verify=ssl_context,
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

    # Create HTTP clients for ChronoGuard
    http_client = create_chronoguard_http_client()
    requests_session = create_chronoguard_requests_session()

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
        except Exception as e:
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

    # Create custom HTTP client for ChronoGuard
    http_client = create_chronoguard_http_client()

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
