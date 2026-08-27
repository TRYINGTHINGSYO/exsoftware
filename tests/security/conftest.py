import pytest

from exsoftware.isolate.acl_prep import PROCESS_ACL_CACHE


@pytest.fixture(autouse=True)
def _clear_process_acl_cache():
    PROCESS_ACL_CACHE.clear()
    yield
    PROCESS_ACL_CACHE.clear()
