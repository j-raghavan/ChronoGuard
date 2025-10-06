"""Audit log export functionality for CSV and JSON formats."""

import csv
import io
import json
from datetime import datetime
from typing import Any, TextIO
from uuid import UUID

from domain.audit.entity import AuditEntry
from domain.audit.repository import AuditRepository
from loguru import logger


class AuditExporter:
    """Export audit logs to various formats."""

    def __init__(self, audit_repository: AuditRepository) -> None:
        """Initialize audit exporter.

        Args:
            audit_repository: Audit repository
        """
        self._repository = audit_repository

    async def export_to_csv(
        self,
        tenant_id: UUID,
        start_time: datetime,
        end_time: datetime,
        output_file: TextIO | None = None,
    ) -> str:
        """Export audit logs to CSV format.

        Args:
            tenant_id: Tenant identifier
            start_time: Start of export period
            end_time: End of export period
            output_file: Optional file object to write to

        Returns:
            CSV content as string (if output_file is None)
        """
        entries = await self._repository.find_by_tenant_time_range(
            tenant_id, start_time, end_time, limit=100000
        )

        logger.info(f"Exporting {len(entries)} audit entries to CSV for tenant {tenant_id}")

        output = output_file or io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "entry_id",
                "tenant_id",
                "agent_id",
                "timestamp",
                "domain",
                "decision",
                "reason",
                "request_method",
                "request_path",
                "risk_score",
            ],
        )

        writer.writeheader()

        for entry in entries:
            row = self._entry_to_csv_dict(entry)
            writer.writerow(row)

        if output_file is None:
            return output.getvalue()

        return ""

    async def export_to_json(
        self,
        tenant_id: UUID,
        start_time: datetime,
        end_time: datetime,
        output_file: TextIO | None = None,
        pretty: bool = True,
    ) -> str:
        """Export audit logs to JSON format.

        Args:
            tenant_id: Tenant identifier
            start_time: Start of export period
            end_time: End of export period
            output_file: Optional file object to write to
            pretty: Whether to pretty-print JSON

        Returns:
            JSON content as string (if output_file is None)
        """
        entries = await self._repository.find_by_tenant_time_range(
            tenant_id, start_time, end_time, limit=100000
        )

        logger.info(f"Exporting {len(entries)} audit entries to JSON for tenant {tenant_id}")

        export_data = {
            "metadata": {
                "tenant_id": str(tenant_id),
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "total_entries": len(entries),
            },
            "entries": [self._entry_to_dict(entry) for entry in entries],
        }

        indent = 2 if pretty else None
        json_content = json.dumps(export_data, indent=indent, default=str)

        if output_file:
            output_file.write(json_content)
            return ""

        return json_content

    def _entry_to_csv_dict(self, entry: AuditEntry) -> dict[str, Any]:
        """Convert audit entry to CSV dictionary."""
        return {
            "entry_id": str(entry.entry_id),
            "tenant_id": str(entry.tenant_id),
            "agent_id": str(entry.agent_id),
            "timestamp": entry.timestamp.isoformat(),
            "domain": str(entry.domain),
            "decision": entry.decision.value,
            "reason": entry.reason,
            "request_method": entry.request_method,
            "request_path": entry.request_path,
            "risk_score": entry.get_risk_score(),
        }

    def _entry_to_dict(self, entry: AuditEntry) -> dict[str, Any]:
        """Convert audit entry to dictionary."""
        return {
            "entry_id": str(entry.entry_id),
            "tenant_id": str(entry.tenant_id),
            "agent_id": str(entry.agent_id),
            "timestamp": entry.timestamp.isoformat(),
            "domain": str(entry.domain),
            "decision": entry.decision.value,
            "reason": entry.reason,
            "request_method": entry.request_method,
            "request_path": entry.request_path,
            "risk_score": entry.get_risk_score(),
            "timed_access_metadata": {
                "is_business_hours": entry.timed_access_metadata.is_business_hours,
                "is_weekend": entry.timed_access_metadata.is_weekend,
                "day_of_week": entry.timed_access_metadata.day_of_week,
                "hour_of_day": entry.timed_access_metadata.hour_of_day,
            },
            "sequence_number": entry.sequence_number,
            "current_hash": entry.current_hash,
        }
