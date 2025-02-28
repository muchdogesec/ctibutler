import os
from urllib.parse import urljoin
import pytest
import requests


base_url = os.environ["CTIBUTLER_URL"]

@pytest.mark.parametrize(
        ["types", "expected_count"],
        [
            [("country",), 249],
            [("region",), 5],
            [("intermediate-region",), 8],
            [("sub-region",), 17],
            [("sub-region", "region"), 17+5],
            [("sub-region", "region", "intermediate-region"), 17+5+8],
        ]
)
def test_location_type(types, expected_count):

    url = urljoin(base_url, f"api/v1/location/objects/")
    resp = requests.get(url, params=dict(location_type=",".join(types)))
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    for d in data['objects']:
        for ref in d['external_references']:
            if ref['source_name'] == 'type':
                assert ref['external_id'] in types, "found unexpected types in response objects"