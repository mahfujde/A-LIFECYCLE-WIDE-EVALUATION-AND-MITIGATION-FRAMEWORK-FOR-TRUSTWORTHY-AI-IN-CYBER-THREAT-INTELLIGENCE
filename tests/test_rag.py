"""Tests for RAG module (unit tests without heavy dependencies)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

class TestVectorStoreInit:
    def test_import(self):
        """Test that rag module can be imported."""
        from cti_shield import rag
        assert hasattr(rag, 'VectorStore')
        assert hasattr(rag, 'search')
        assert hasattr(rag, 'build_and_save')

    def test_get_vector_store(self):
        """Test singleton accessor."""
        try:
            from cti_shield.rag import get_vector_store
            store = get_vector_store()
            assert store is not None
            assert store.total_vectors >= 0
        except ModuleNotFoundError:
            pytest.skip("faiss-cpu not installed")

class TestCacheSetup:
    def test_cache_exists(self):
        from cti_shield.rag import _query_cache
        assert _query_cache is not None
        assert _query_cache.maxsize == 256
