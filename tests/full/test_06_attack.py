import os
from urllib.parse import urljoin
import pytest


@pytest.mark.parametrize(
    ["include_deprecated", "include_revoked", "version", "expected_count"],
    [
        [True, True, "", 2187],
        [True, False, "", 2048],
        [False, True, "", 1918],
        [False, False, "", 1779],
        [True, True, "15.1", 2103],
        [True, False, "15.1", 1964],
        [False, True, "15.1", 1834],
        [False, False, "15.1", 1695],
    ],
)
def test_deprecated_and_revoked(
    client, include_deprecated, include_revoked, version, expected_count
):
    url = f"/api/v1/attack-enterprise/objects/"
    resp = client.get(
        url,
        query_params=dict(
            include_deprecated=include_deprecated,
            include_revoked=include_revoked,
            attack_version=version,
        ),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    for d in data["objects"]:
        if not include_revoked:
            assert d.get("revoked", False) == False
        if not include_deprecated:
            assert d.get("x_mitre_deprecated", False) == False
