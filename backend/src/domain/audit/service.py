"""Audit domain service for secure audit logging and chain verification."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from domain.audit.entity import (
    AccessDecision,
    AuditEntry,
    ChainVerificationResult,
    TimedAccessContext,
)
from domain.audit.repository import AuditRepository
from domain.common.exceptions import BusinessRuleViolationError, ValidationError
from domain.common.value_objects import DomainName


class AccessRequest:
    """Request object for audit logging."""

    def __init__(
        self,
        tenant_id: UUID,
        agent_id: UUID,
        domain: str,
        decision: AccessDecision,
        reason: str = "",
        policy_id: UUID | None = None,
        rule_id: UUID | None = None,
        request_method: str = "GET",
        request_path: str = "/",
        user_agent: str | None = None,
        source_ip: str | None = None,
        response_status: int | None = None,
        response_size_bytes: int | None = None,
        processing_time_ms: float | None = None,
        timestamp: datetime | None = None,
        metadata: dict[str, str] | None = None,
    ) -> None:
        """Initialize access request.

        Args:
            tenant_id: Tenant identifier
            agent_id: Agent identifier
            domain: Domain being accessed
            decision: Access control decision
            reason: Reason for the decision
            policy_id: Policy that made the decision
            rule_id: Specific rule that matched
            request_method: HTTP method
            request_path: Request path
            user_agent: User agent string
            source_ip: Source IP address
            response_status: HTTP response status
            response_size_bytes: Response size in bytes
            processing_time_ms: Processing time in milliseconds
            timestamp: Request timestamp
            metadata: Additional metadata
        """
        self.tenant_id = tenant_id
        self.agent_id = agent_id
        self.domain = domain
        self.decision = decision
        self.reason = reason
        self.policy_id = policy_id
        self.rule_id = rule_id
        self.request_method = request_method
        self.request_path = request_path
        self.user_agent = user_agent
        self.source_ip = source_ip
        self.response_status = response_status
        self.response_size_bytes = response_size_bytes
        self.processing_time_ms = processing_time_ms
        self.timestamp = timestamp or datetime.now(UTC)
        self.metadata = metadata or {}


class AuditService:
    """Domain service for audit operations and chain integrity."""

    def __init__(
        self,
        audit_repository: AuditRepository,
        secret_key: bytes | None = None,
    ) -> None:
        """Initialize audit service.

        Args:
            audit_repository: Repository for audit persistence
            secret_key: Optional secret key for hash chaining
        """
        self._repository = audit_repository
        self._secret_key = secret_key

    async def record_access(self, request: AccessRequest) -> AuditEntry:
        """Record an access attempt with hash chaining.

        Args:
            request: Access request to record

        Returns:
            Created audit entry

        Raises:
            BusinessRuleViolationError: If recording violates business rules
            ValidationError: If request data is invalid
        """
        # Validate request data
        self._validate_access_request(request)

        # Get previous entry for hash chaining
        previous_entry = await self._repository.get_latest_entry_for_agent(
            request.tenant_id, request.agent_id
        )

        # Get next sequence number
        sequence_number = await self._repository.get_next_sequence_number(
            request.tenant_id, request.agent_id
        )

        # Create timed access metadata
        timed_metadata = TimedAccessContext.create_from_timestamp(request.timestamp)

        # Build audit entry
        entry = AuditEntry(
            tenant_id=request.tenant_id,
            agent_id=request.agent_id,
            timestamp=request.timestamp,
            domain=DomainName(value=request.domain),
            decision=request.decision,
            reason=request.reason,
            policy_id=request.policy_id,
            rule_id=request.rule_id,
            request_method=request.request_method,
            request_path=request.request_path,
            user_agent=request.user_agent,
            source_ip=request.source_ip,
            response_status=request.response_status,
            response_size_bytes=request.response_size_bytes,
            processing_time_ms=request.processing_time_ms,
            timed_access_metadata=timed_metadata,
            sequence_number=sequence_number,
            metadata=request.metadata,
        )

        # Calculate hash with chaining
        previous_hash = previous_entry.current_hash if previous_entry else ""
        entry_with_hash = entry.with_hash(previous_hash, self._secret_key)

        # Save entry
        await self._repository.save(entry_with_hash)

        return entry_with_hash

    async def verify_agent_chain(
        self,
        tenant_id: UUID,
        agent_id: UUID,
        start_sequence: int = 0,
        end_sequence: int | None = None,
    ) -> ChainVerificationResult:
        """Verify audit chain integrity for an agent.

        Args:
            tenant_id: Tenant identifier
            agent_id: Agent identifier
            start_sequence: Starting sequence number
            end_sequence: Ending sequence number (None for latest)

        Returns:
            Chain verification result

        Raises:
            BusinessRuleViolationError: If verification fails due to business rules
        """
        return await self._repository.verify_chain_integrity(
            tenant_id, agent_id, start_sequence, end_sequence, self._secret_key
        )

    async def detect_chain_tampering(self, tenant_id: UUID, agent_id: UUID) -> list[str]:
        """Detect potential tampering in audit chains.

        Args:
            tenant_id: Tenant identifier
            agent_id: Agent identifier

        Returns:
            List of tampering indicators

        Raises:
            BusinessRuleViolationError: If detection fails
        """
        tampering_indicators = []

        # Check for sequence gaps
        gaps = await self._repository.find_chain_gaps(tenant_id, agent_id)
        if gaps:
            tampering_indicators.append(f"Sequence gaps detected: {len(gaps)} gaps found")

        # Verify chain integrity
        verification = await self.verify_agent_chain(tenant_id, agent_id)
        if not verification.is_valid:
            tampering_indicators.extend(verification.errors)

        # Check for time anomalies
        time_anomalies = await self._detect_time_anomalies(tenant_id, agent_id)
        tampering_indicators.extend(time_anomalies)

        return tampering_indicators

    async def get_audit_statistics(
        self,
        tenant_id: UUID,
        start_time: datetime,
        end_time: datetime,
    ) -> dict[str, Any]:
        """Get comprehensive audit statistics.

        Args:
            tenant_id: Tenant identifier
            start_time: Start time for statistics
            end_time: End time for statistics

        Returns:
            Dictionary with audit statistics
        """
        # Get basic access statistics
        access_stats = await self._repository.get_access_statistics(tenant_id, start_time, end_time)

        # Get decision breakdown
        decision_counts = {}
        for decision in AccessDecision:
            count = await self._repository.count_entries_by_decision(
                tenant_id, decision, start_time, end_time
            )
            decision_counts[decision.value] = count

        # Get top domains
        top_domains = await self._repository.get_top_domains_by_access(
            tenant_id, start_time, end_time, limit=10
        )

        # Get suspicious patterns
        suspicious_patterns = await self._repository.find_suspicious_patterns(
            tenant_id, lookback_hours=24
        )

        return {
            "period": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
            },
            "access_statistics": access_stats,
            "decision_counts": decision_counts,
            "top_domains": [{"domain": domain, "count": count} for domain, count in top_domains],
            "suspicious_patterns": suspicious_patterns,
            "total_entries": sum(decision_counts.values()),
        }

    async def find_security_incidents(
        self,
        tenant_id: UUID,
        lookback_hours: int = 24,
        min_severity: str = "medium",
    ) -> list[dict[str, Any]]:
        """Find potential security incidents from audit logs.

        Args:
            tenant_id: Tenant identifier
            lookback_hours: Hours to look back for incidents
            min_severity: Minimum severity level ("low", "medium", "high")

        Returns:
            List of security incident summaries
        """
        incidents = []

        # Find suspicious access patterns
        suspicious_patterns = await self._repository.find_suspicious_patterns(
            tenant_id, lookback_hours
        )

        for pattern in suspicious_patterns:
            severity = self._calculate_incident_severity(pattern)
            if self._meets_severity_threshold(severity, min_severity):
                incidents.append(
                    {
                        "type": "suspicious_access_pattern",
                        "severity": severity,
                        "description": pattern.get(
                            "description", "Suspicious access pattern detected"
                        ),
                        "details": pattern,
                        "timestamp": datetime.now(UTC).isoformat(),
                    }
                )

        # Find chain integrity issues
        # This would require checking multiple agents
        # Implementation depends on specific requirements

        return incidents

    async def export_audit_logs(
        self,
        tenant_id: UUID,
        start_time: datetime,
        end_time: datetime,
        export_format: str = "json",
        batch_size: int = 1000,
    ) -> list[dict[str, Any]]:
        """Export audit logs for external processing.

        Args:
            tenant_id: Tenant identifier
            start_time: Start time for export
            end_time: End time for export
            export_format: Export format ("json", "csv")
            batch_size: Batch size for processing

        Returns:
            List of exported audit entries

        Raises:
            ValidationError: If export parameters are invalid
        """
        if export_format not in {"json", "csv"}:
            raise ValidationError(
                f"Unsupported export format: {export_format}",
                field="export_format",
                value=export_format,
            )

        exported_entries = []
        last_processed_id = None

        while True:
            batch, next_cursor = await self._repository.find_entries_for_export(
                tenant_id, start_time, end_time, batch_size, last_processed_id
            )

            if not batch:
                break

            # Convert to export format
            for entry in batch:
                if export_format == "json":
                    exported_entries.append(entry.to_json_dict())
                elif export_format == "csv":
                    # Convert to flat dictionary for CSV
                    csv_dict = self._entry_to_csv_dict(entry)
                    exported_entries.append(csv_dict)

            last_processed_id = next_cursor
            if not next_cursor:
                break

        return exported_entries

    async def cleanup_old_audit_logs(
        self,
        tenant_id: UUID,
        retention_days: int,
        archive_before_delete: bool = True,
        storage_path: str | None = None,
    ) -> dict[str, int]:
        """Clean up old audit logs based on retention policy.

        Args:
            tenant_id: Tenant identifier
            retention_days: Number of days to retain logs
            archive_before_delete: Whether to archive before deletion
            storage_path: Path for archival storage

        Returns:
            Dictionary with cleanup statistics

        Raises:
            BusinessRuleViolationError: If cleanup violates business rules
        """
        if retention_days < 30:
            raise BusinessRuleViolationError(
                "Minimum retention period is 30 days",
                rule_name="minimum_audit_retention",
                context={"requested_days": retention_days},
            )

        cutoff_date = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff_date = cutoff_date - timedelta(days=retention_days)

        archived_count = 0
        deleted_count = 0

        if archive_before_delete and storage_path:
            archived_count = await self._repository.archive_entries_to_storage(
                tenant_id, cutoff_date, storage_path
            )

        deleted_count = await self._repository.cleanup_old_entries(tenant_id, cutoff_date)

        return {
            "cutoff_date": cutoff_date.isoformat(),
            "archived_entries": archived_count,
            "deleted_entries": deleted_count,
        }

    def _validate_access_request(self, request: AccessRequest) -> None:
        """Validate access request data.

        Args:
            request: Access request to validate

        Raises:
            ValidationError: If request is invalid
        """
        if not request.domain:
            raise ValidationError(
                "Domain is required for audit logging",
                field="domain",
                value=request.domain,
            )

        if len(request.reason) > 500:
            raise ValidationError(
                f"Reason too long: {len(request.reason)} characters (max 500)",
                field="reason",
                value=len(request.reason),
            )

        # Validate timestamp is not too far in the future
        max_future_minutes = 5
        max_future_time = datetime.now(UTC) + timedelta(minutes=max_future_minutes)

        if request.timestamp > max_future_time:
            raise ValidationError(
                "Timestamp cannot be more than 5 minutes in the future",
                field="timestamp",
                value=request.timestamp.isoformat(),
            )

    async def _detect_time_anomalies(self, tenant_id: UUID, agent_id: UUID) -> list[str]:
        """Detect time-based anomalies in audit chain.

        Args:
            tenant_id: Tenant identifier
            agent_id: Agent identifier

        Returns:
            List of time anomaly descriptions
        """
        anomalies: list[str] = []

        # Get recent entries for time analysis
        from datetime import timedelta

        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(hours=24)  # Last 24 hours

        entries = await self._repository.find_by_agent_time_range(
            agent_id, start_time, end_time, limit=1000
        )

        if len(entries) < 2:
            return anomalies

        # Check for time sequence violations
        for i in range(1, len(entries)):
            current = entries[i]
            previous = entries[i - 1]

            # Check if timestamps are in proper sequence
            if current.timestamp < previous.timestamp:
                anomalies.append(
                    f"Time sequence violation: entry {current.entry_id} "
                    f"has timestamp before previous entry"
                )

            # Check for suspiciously large time gaps
            time_diff = (current.timestamp - previous.timestamp).total_seconds()
            if time_diff > 3600:  # More than 1 hour gap
                anomalies.append(
                    f"Large time gap detected: {time_diff / 3600:.1f} hours "
                    f"between entries {previous.entry_id} and {current.entry_id}"
                )

        return anomalies

    def _calculate_incident_severity(self, pattern: dict[str, Any]) -> str:
        """Calculate severity level for a suspicious pattern.

        Args:
            pattern: Suspicious pattern data

        Returns:
            Severity level ("low", "medium", "high", "critical")
        """
        # Simplified severity calculation
        failed_attempts = pattern.get("failed_attempts", 0)
        unique_domains = pattern.get("unique_domains", 0)
        off_hours_percentage = pattern.get("off_hours_percentage", 0)

        score = 0
        if failed_attempts > 50:
            score += 3
        elif failed_attempts > 20:
            score += 2
        elif failed_attempts > 10:
            score += 1

        if unique_domains > 20:
            score += 2
        elif unique_domains > 10:
            score += 1

        if off_hours_percentage > 80:
            score += 2
        elif off_hours_percentage > 50:
            score += 1

        if score >= 6:
            return "critical"
        if score >= 4:
            return "high"
        if score >= 2:
            return "medium"
        return "low"

    def _meets_severity_threshold(self, severity: str, min_severity: str) -> bool:
        """Check if severity meets minimum threshold.

        Args:
            severity: Actual severity level
            min_severity: Minimum required severity

        Returns:
            True if severity meets threshold
        """
        severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return severity_levels.get(severity, 0) >= severity_levels.get(min_severity, 0)

    def _entry_to_csv_dict(self, entry: AuditEntry) -> dict[str, str]:
        """Convert audit entry to flat dictionary for CSV export.

        Args:
            entry: Audit entry to convert

        Returns:
            Flat dictionary representation
        """
        return {
            "entry_id": str(entry.entry_id),
            "tenant_id": str(entry.tenant_id),
            "agent_id": str(entry.agent_id),
            "timestamp": entry.timestamp.isoformat(),
            "domain": entry.domain.value,
            "decision": entry.decision.value,
            "reason": entry.reason,
            "request_method": entry.request_method,
            "request_path": entry.request_path,
            "source_ip": entry.source_ip or "",
            "user_agent": entry.user_agent or "",
            "response_status": str(entry.response_status or ""),
            "processing_time_ms": str(entry.processing_time_ms or ""),
            "sequence_number": str(entry.sequence_number),
            "risk_score": str(entry.get_risk_score()),
        }
