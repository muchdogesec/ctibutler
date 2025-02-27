import os
from urllib.parse import urljoin
import pytest
import requests

base_url = os.environ["CTIBUTLER_URL"]


@pytest.mark.parametrize(
    ["path", "expected_result_count", "params"],
    [
        pytest.param("attack-enterprise", 1765, None),
        pytest.param("attack-enterprise", 1765, dict(attack_version="16.0")),
        pytest.param("attack-enterprise", 1695, dict(attack_version="15.1")),
    ],
)
def test_path_objects_count(path, expected_result_count, params):
    url = urljoin(base_url, f"api/v1/{path}/objects/")
    resp = requests.get(url, params=params)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_result_count



@pytest.mark.parametrize(
    ["path", "expected_versions"],
    [
        pytest.param("capec", ("3.9", "3.8")),
        pytest.param("attack-enterprise", ["16.0", "15.1"]),
        pytest.param("atlas", ["4.7.0", "4.5.2"]),
        pytest.param("cwe", ["4.16", "4.15"]),
        pytest.param("location", ["e19e035"]),
        pytest.param("disarm", ["1.6", "1.5"]),
    ],
)
def test_path_versions(path, expected_versions):
    url = urljoin(base_url, f"api/v1/{path}/versions/")
    resp = requests.get(url)
    assert resp.status_code == 200
    versions = tuple(resp.json()["versions"])
    assert versions == tuple(expected_versions)


@pytest.mark.parametrize(
    ["path", "object_id", "expected_versions"],
    [
        pytest.param(
            "cwe",
            "CWE-494",
            [{"modified": "2024-02-29T00:00:00.000Z", "versions": ["4.16", "4.15"]}],
        ),
        pytest.param(
            "capec",
            "CAPEC-112",
            [{"modified": "2022-09-29T00:00:00.000Z", "versions": ["3.9", "3.8"]}],
        ),
        pytest.param(
            "attack-enterprise",
            "T1021.005",
            [
                {"modified": "2024-09-12T15:20:07.264Z", "versions": ["16.0"]},
                {"modified": "2023-05-09T14:00:00.188Z", "versions": ["15.1"]},
            ],
        ),
    ],
)
def test_object_versions(path, object_id, expected_versions):
    url = urljoin(base_url, f"api/v1/{path}/objects/{object_id}/versions/")
    resp = requests.get(url)
    assert resp.status_code == 200
    versions = resp.json()
    assert versions == expected_versions

@pytest.mark.parametrize(
    ["path", "object_id", "expected_count", "params"],
    [
        pytest.param("capec", "CAPEC-185", 14, None),
        pytest.param("capec", "CAPEC-185", 14, dict(capec_version="3.9")),
        pytest.param("capec", "CAPEC-185", 16, dict(capec_version="3.8")),
        ##############
        # pytest.param("attack-enterprise", 1765, dict(attack_version="16.0")),
        # pytest.param("attack-enterprise", 1695, dict(attack_version="15.1")),
        ##############
        pytest.param("disarm", "T0086.003", 11, None),
        pytest.param("disarm", "T0086.003", 11, dict(disarm_version='1.5')),
    ],
)
def test_object_count_bundle(path, object_id, expected_count, params):
    url = urljoin(base_url, f"api/v1/{path}/objects/{object_id}/bundle/")
    resp = requests.get(url, params=params)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    ## check uniqueness of objects by id
    assert len({x['id'] for x in data['objects']}) == data['page_results_count'], "response contains duplicates"


@pytest.mark.parametrize(
    ["path", "object_id", "expected_modified", "params"],
    [
        pytest.param("capec", "CAPEC-185", "2022-09-29T00:00:00.000Z", None),
        pytest.param("capec", "CAPEC-185", "2022-09-29T00:00:00.000Z", dict(capec_version="3.9")),
        pytest.param("capec", "CAPEC-185", "2022-09-29T00:00:00.000Z", dict(capec_version="3.8")),
        ##############
        pytest.param("attack-enterprise", "T1021.005", "2024-09-12T15:20:07.264Z", None),
        pytest.param("attack-enterprise", "T1021.005", "2024-09-12T15:20:07.264Z", dict(capec_version="16.0")),
        pytest.param("attack-enterprise", "T1021.005", "2023-05-09T14:00:00.188Z", dict(capec_version="15.1")),
        ##############
        pytest.param("disarm", "T0086.003", "2024-11-22T00:00:00.000Z", None),
        pytest.param("disarm", "T0086.003", "2024-11-22T00:00:00.000Z", dict(disarm_version="1.6")),
        pytest.param("disarm", "T0086.003", "2024-08-02T00:00:00.000Z", dict(disarm_version="1.5")),
    ],
)
def test_object_modified(path, object_id, expected_modified, params):
    url = urljoin(base_url, f"api/v1/{path}/objects/{object_id}/")
    resp = requests.get(url, params=params)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["objects"]) == 1
    assert data["objects"][0]["modified"] == expected_modified



@pytest.mark.parametrize(
    ["path", "object_id", "expected_count", "params"],
    [
        pytest.param("capec", "CAPEC-185", 8, None),
        pytest.param("capec", "CAPEC-185", 5, dict(relationship_direction='source_ref')),
        pytest.param("capec", "CAPEC-185", 8, dict(capec_version="3.9")),
        pytest.param("capec", "CAPEC-185", 9, dict(capec_version="3.8")),
        pytest.param("capec", "CAPEC-185", 4, dict(capec_version="3.8", relationship_direction='target_ref')),
        ##############
        pytest.param("disarm", "T0086.003", 5, None),
        pytest.param("disarm", "T0086.003", 5, dict(disarm_version="1.5")),
    ],
)
def test_object_count_relationships(path, object_id, expected_count, params):
    url = urljoin(base_url, f"api/v1/{path}/objects/{object_id}/relationships/")
    resp = requests.get(url, params=params)
    assert resp.status_code == 200, f"expected status_code 200, got {resp.reason}"
    data = resp.json()
    assert data["total_results_count"] == expected_count, "unexpected count"
    ## check uniqueness of objects by id
    assert len({x['id'] for x in data['relationships']}) == data['page_results_count'], "response contains duplicates"