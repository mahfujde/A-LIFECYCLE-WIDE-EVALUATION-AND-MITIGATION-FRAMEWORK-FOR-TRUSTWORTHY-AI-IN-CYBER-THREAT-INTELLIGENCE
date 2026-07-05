"""Tests for the __init__ module."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_version():
    from cti_shield import __version__
    assert __version__ == "1.0.0"


def test_author():
    from cti_shield import __author__
    assert "CTI-Shield" in __author__
