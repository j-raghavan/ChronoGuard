"""Command-line utility to load ChronoGuard sample data."""

from __future__ import annotations

import asyncio
import sys

from application.seed import SeedPreconditionError, seed_sample_data
from loguru import logger
from presentation.api.dependencies import get_agent_repository


async def main() -> None:
    """Seed the database using the configured repository."""

    repo = get_agent_repository()
    stats = await seed_sample_data(repo.session_factory)
    logger.success(
        "Seeded database with sample data",
        agents=stats.agents_created,
        policies=stats.policies_created,
        audit_entries=stats.audit_entries_created,
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except SeedPreconditionError as exc:
        logger.error(str(exc))
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Seeding failed")
        sys.exit(1)
