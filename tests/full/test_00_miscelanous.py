from ctibutler.server.arango_helpers import get_versions
from ctibutler.server.utils import split_mitre_version
import pytest


@pytest.mark.parametrize(
    ["v", "expected_splits"],
    [
        ("1.1", (1, 1)),
        ("1.2", (1, 2)),
        ("1.2-3.1", (1, 2, 3, 1)),
        ("1.2-3.1-beta", (1, 2, 3, 1, 'beta')),
    ],
)
def test_split_mitre_version(v, expected_splits):
    assert split_mitre_version(v) == expected_splits

def test_get_versions__fails_silently():
    assert get_versions('bad-collection') == []