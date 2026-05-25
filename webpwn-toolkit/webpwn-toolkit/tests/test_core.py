"""
Core functionality tests for WebPwn Toolkit.
Ensures configuration and basic utilities function as expected.
"""

import os
import sys
import pytest
from typing import Dict, Any

# Add the root directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import load_config, WebPwnToolkit


@pytest.fixture
def default_config() -> Dict[str, Any]:
    """Fixture to load default configuration."""
    return load_config()


def test_load_config_default(default_config: Dict[str, Any]) -> None:
    """Test loading default configuration."""
    assert isinstance(default_config, dict)


def test_load_config_stealth() -> None:
    """Test loading stealth profile."""
    config = load_config("profiles/stealth.yaml")
    assert config.get("name") == "stealth"
    assert config.get("threads") == 2
    assert config.get("timeout") == 30


def test_load_config_aggressive() -> None:
    """Test loading aggressive profile."""
    config = load_config("profiles/aggressive.yaml")
    assert config.get("name") == "aggressive"
    assert config.get("threads") == 50
    assert config.get("timeout") == 5


def test_toolkit_initialization() -> None:
    """Test toolkit initialization with stealth profile."""
    toolkit = WebPwnToolkit("profiles/stealth.yaml")
    assert toolkit.config.get("name") == "stealth"
