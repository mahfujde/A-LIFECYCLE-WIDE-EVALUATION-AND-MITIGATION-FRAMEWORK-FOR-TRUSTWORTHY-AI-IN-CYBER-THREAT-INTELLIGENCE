"""Pytest configuration and shared fixtures."""
import sys
from pathlib import Path

# Add project root to path for all tests
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
