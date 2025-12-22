"""
conftest.py - Pytest Configuration and Fixtures

Provides shared fixtures and configuration for all test modules.

Author: Claude Opus 4.5
Date: 2025-12-18
"""

import os
import sys
import pytest
import tempfile

# Add src to path for all tests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))


# ============================================================================
# PYTEST MARKERS
# ============================================================================

def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: integration tests (may be slower)")
    config.addinivalue_line("markers", "live: tests requiring live network servers")
    config.addinivalue_line("markers", "slow: slow-running tests")
    config.addinivalue_line("markers", "database: tests requiring database")


# ============================================================================
# SHARED FIXTURES
# ============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp = tempfile.mkdtemp()
    yield temp
    # Cleanup
    import shutil
    if os.path.exists(temp):
        shutil.rmtree(temp)


@pytest.fixture
def temp_db_path(temp_dir):
    """Create a path for temporary database."""
    return os.path.join(temp_dir, "test_qmail.db")


@pytest.fixture
def db_handle(temp_db_path):
    """Create and initialize a test database."""
    from database import init_database, close_database
    err, handle = init_database(temp_db_path)
    if err != 0:  # DatabaseErrorCode.SUCCESS
        pytest.fail(f"Failed to create test database: {err}")
    yield handle
    close_database(handle)


@pytest.fixture
def mock_identity():
    """Create a mock identity for testing."""
    from test_utils import create_mock_identity
    return create_mock_identity()


@pytest.fixture
def mock_request():
    """Create a mock SendEmailRequest for testing."""
    from test_utils import create_mock_request
    return create_mock_request(to_recipients=["0006.1.12345678"])


@pytest.fixture
def locker_code():
    """Generate a test locker code."""
    return os.urandom(8)


@pytest.fixture
def file_group_guid():
    """Generate a test file group GUID."""
    return os.urandom(16)


@pytest.fixture
def an():
    """Generate a test AN (Authenticity Number)."""
    return os.urandom(16)


@pytest.fixture
def locker_key():
    """Generate a test locker payment key."""
    return os.urandom(16)


@pytest.fixture
def mock_servers():
    """Create mock server configurations."""
    from test_utils import create_mock_servers
    return create_mock_servers(5)


@pytest.fixture
def mock_upload_results():
    """Create mock upload results."""
    from test_utils import create_mock_upload_results
    return create_mock_upload_results(5)


# ============================================================================
# SKIP MARKERS
# ============================================================================

def pytest_collection_modifyitems(config, items):
    """Add skip markers based on conditions."""
    # Skip live tests unless explicitly requested
    if not config.getoption("--run-live", default=False):
        skip_live = pytest.mark.skip(reason="Live tests disabled. Use --run-live to enable.")
        for item in items:
            if "live" in item.keywords:
                item.add_marker(skip_live)


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Run live network tests"
    )
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests"
    )


# ============================================================================
# TEST REPORTING
# ============================================================================

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Add extra info to test reports."""
    outcome = yield
    report = outcome.get_result()

    # Add test duration info
    if report.when == "call":
        if hasattr(item, 'fixturenames'):
            report.fixtures_used = item.fixturenames
