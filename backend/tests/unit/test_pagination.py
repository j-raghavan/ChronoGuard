import pytest
from pydantic import ValidationError

from application.pagination import PaginatedResponse, PaginationParams


class TestPaginationParams:
    def test_defaults(self):
        """Test default values."""
        params = PaginationParams()
        assert params.page == 1
        assert params.limit == 50
        assert params.offset == 0

    def test_custom_values(self):
        """Test custom values."""
        params = PaginationParams(page=2, limit=20)
        assert params.page == 2
        assert params.limit == 20
        assert params.offset == 20

    def test_offset_calculation(self):
        """Test offset calculation based on page and limit."""
        params = PaginationParams(page=1, limit=10)
        assert params.offset == 0

        params = PaginationParams(page=3, limit=10)
        assert params.offset == 20

    def test_validation_success(self):
        """Test validation with valid values."""
        PaginationParams(limit=1)
        PaginationParams(limit=100)
        PaginationParams(limit=50)

    def test_validation_error_limit_too_low(self):
        """Test validation fails when limit is too low."""
        with pytest.raises(ValidationError) as exc:
            PaginationParams(limit=0)
        # Pydantic v2 might throw standard error for ge/le constraints before custom validator
        msg = str(exc.value)
        assert "Limit must be between 1 and 100" in msg or "greater than or equal to 1" in msg

    def test_validation_error_limit_too_high(self):
        """Test validation fails when limit is too high."""
        with pytest.raises(ValidationError) as exc:
            PaginationParams(limit=101)
        # Pydantic v2 might throw standard error for ge/le constraints before custom validator
        msg = str(exc.value)
        assert "Limit must be between 1 and 100" in msg or "less than or equal to 100" in msg

    def test_validation_error_page_too_low(self):
        """Test validation fails when page is less than 1."""
        with pytest.raises(ValidationError) as exc:
            PaginationParams(page=0)
        assert "greater than or equal to 1" in str(exc.value)


class TestPaginatedResponse:
    def test_create(self):
        """Test creating a paginated response."""
        items = ["a", "b", "c"]
        total = 10
        params = PaginationParams(page=1, limit=5)

        response = PaginatedResponse.create(items, total, params)

        assert response.items == items
        assert response.total == total
        assert response.page == 1
        assert response.limit == 5
        assert response.total_pages == 2

    def test_create_empty(self):
        """Test creating an empty paginated response."""
        items = []
        total = 0
        params = PaginationParams()

        response = PaginatedResponse.create(items, total, params)

        assert response.items == []
        assert response.total == 0
        assert response.total_pages == 0

    def test_pagination_math(self):
        """Test total_pages calculation."""
        # Total 11, limit 5 -> 3 pages
        response = PaginatedResponse.create([], 11, PaginationParams(limit=5))
        assert response.total_pages == 3

        # Total 10, limit 5 -> 2 pages
        response = PaginatedResponse.create([], 10, PaginationParams(limit=5))
        assert response.total_pages == 2

        # Total 0, limit 5 -> 0 pages
        response = PaginatedResponse.create([], 0, PaginationParams(limit=5))
        assert response.total_pages == 0

    def test_serialization(self):
        """Test that the response can be serialized (sanity check)."""
        items = [1, 2]
        total = 10
        params = PaginationParams(limit=5)
        response = PaginatedResponse[int].create(items, total, params)
        
        data = response.model_dump()
        assert data["items"] == [1, 2]
        assert data["total"] == 10
        assert data["limit"] == 5
        assert data["total_pages"] == 2
