from __future__ import annotations

import math
from typing import Generic, TypeVar

from typing import Generic, TypeVar

from pydantic import BaseModel, Field, field_validator

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Standard pagination parameters."""

    page: int = Field(default=1, ge=1, description="Page number")
    limit: int = Field(default=50, ge=1, le=100, description="Items per page")

    @property
    def offset(self) -> int:
        """Calculate offset for database queries."""
        return (self.page - 1) * self.limit

    @field_validator("limit")
    @classmethod
    def validate_limit(cls, v: int) -> int:
        """Validate limit is within acceptable range."""
        if not 1 <= v <= 100:
            raise ValueError("Limit must be between 1 and 100")
        return v


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""

    items: list[T]
    total: int
    page: int
    limit: int
    total_pages: int

    @classmethod
    def create(cls, items: list[T], total: int, params: PaginationParams) -> PaginatedResponse[T]:
        """Create a paginated response from items and total count."""
        total_pages = math.ceil(total / params.limit) if params.limit > 0 else 0
        return cls(
            items=items,
            total=total,
            page=params.page,
            limit=params.limit,
            total_pages=total_pages,
        )
