from __future__ import annotations

import math
from typing import Generic, TypeVar

from pydantic import BaseModel, Field


T = TypeVar("T")


class PaginationParams(BaseModel):
    """Standard pagination parameters."""

    page: int = Field(default=1, ge=1, description="Page number")
    limit: int = Field(default=50, ge=1, le=100, description="Items per page")

    @property
    def offset(self) -> int:
        """Calculate offset for database queries."""
        return (self.page - 1) * self.limit


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
