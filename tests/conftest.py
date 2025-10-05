"""Pytest configuration and fixtures."""

import pytest


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test (deselect with '-m \"not integration\"')"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )


@pytest.fixture
def sample_user():
    """Provide a sample user for testing."""
    return {
        "id": "test_user_123",
        "name": "Test User",
        "role": "user",
        "permissions": ["read", "write"]
    }


@pytest.fixture
def admin_user():
    """Provide an admin user for testing."""
    return {
        "id": "admin_123",
        "name": "Admin User",
        "role": "admin",
        "permissions": ["read", "write", "delete", "admin"]
    }


@pytest.fixture
def mock_llm_response():
    """Provide a mock LLM response for testing."""
    return {
        "content": "This is a test response",
        "model": "test-model",
        "tokens": 10
    }
