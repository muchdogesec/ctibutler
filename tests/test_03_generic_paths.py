import os
from urllib.parse import urljoin
import pytest
import requests

base_url = os.environ["CTIBUTLER_URL"]

FAKE_VERSION = "1.9.1.9"
@pytest.mark.parametrize(
    ["path", "expected_result_count", "params"],
    [
        ######## ATT&CK #######
        pytest.param("attack-enterprise", 1765, None),
        pytest.param("attack-enterprise", 1765, dict(attack_version="16.0")),
        pytest.param("attack-enterprise", 1695, dict(attack_version="15.1")),
        pytest.param("attack-enterprise", 0, dict(attack_version=FAKE_VERSION)),
        ######## CAPEC #######
        pytest.param("capec", 1494, None),
        pytest.param("capec", 1494, dict(capec_version="3.9")),
        pytest.param("capec", 1471, dict(capec_version="3.8")),
        pytest.param("capec", 0, dict(capec_version=FAKE_VERSION)),
        ######## CWE #######
        pytest.param("cwe", 1297, None),
        pytest.param("cwe", 1297, dict(cwe_version="4.16")),
        pytest.param("cwe", 1296, dict(cwe_version="4.15")),
        pytest.param("cwe", 0, dict(cwe_version=FAKE_VERSION)),
        ######## DISARM #######
        pytest.param("disarm", 410, None),
        pytest.param("disarm", 410, dict(disarm_version="1.6")),
        pytest.param("disarm", 348, dict(disarm_version="1.5")),
        pytest.param("disarm", 0, dict(disarm_version=FAKE_VERSION)),
        ######## ATLAS #######
        pytest.param("atlas", 133, None),
        pytest.param("atlas", 133, dict(atlas_version="4.7.0")),
        pytest.param("atlas", 118, dict(atlas_version="4.5.2")),
        pytest.param("atlas", 0, dict(atlas_version=FAKE_VERSION)),
        ######## Location #######
        pytest.param("location", 279, None),
        pytest.param("location", 279, dict(location_version="e19e035")),
        pytest.param("location", 0, dict(location_version=FAKE_VERSION)),
    ],
)
def test_path_objects_count(path, expected_result_count, params):
    url = urljoin(base_url, f"api/v1/{path}/objects/")
    resp = requests.get(url, params=params)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_result_count
    ## check uniqueness of objects by id
    assert len({x['id'] for x in data['objects']}) == data['page_results_count'], "response contains duplicates"


@pytest.mark.parametrize(
    ["path", "expected_versions"],
    [
        pytest.param("capec", ["3.9", "3.8"]),
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
            "attack-enterprise",
            "T1021.005",
            [
                {"modified": "2024-09-12T15:20:07.264Z", "versions": ["16.0"]},
                {"modified": "2023-05-09T14:00:00.188Z", "versions": ["15.1"]},
            ],
        ),
        pytest.param(
            "capec",
            "CAPEC-112",
            [{"modified": "2022-09-29T00:00:00.000Z", "versions": ["3.9", "3.8"]}],
        ),
        pytest.param(
            "cwe",
            "CWE-494",
            [{"modified": "2024-02-29T00:00:00.000Z", "versions": ["4.16", "4.15"]}],
        ),
        pytest.param(
            "disarm",
            "T0002",
            [
                {"modified": "2024-11-22T00:00:00.000Z", "versions": ["1.6"]},
                {"modified": "2024-08-02T00:00:00.000Z", "versions": ["1.5"]},
            ],
        ),
        pytest.param(
            "atlas",
            "AML.M0002",
            [
                {"modified": "2024-06-24T20:23:47.459724Z", "versions": ["4.5.2"]},
                {"modified": "2023-10-12T00:00:00.000Z", "versions": ["4.7.0"]},
            ],
        ),
        pytest.param(
            "location",
            "US",
            [{"modified": "2020-01-01T00:00:00.000Z", "versions": ["e19e035"]}],
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
        ############## ATTACK
        pytest.param("attack-enterprise", "T1021.005", 46, None),
        pytest.param("attack-enterprise", "T1021.005", 46, dict(attack_version="16.0")),
        pytest.param("attack-enterprise", "T1021.005", 44, dict(attack_version="15.1")),
        pytest.param("attack-enterprise", "T1021.005", 0, dict(attack_version=FAKE_VERSION)),
        ############## CAPEC
        pytest.param("capec", "CAPEC-185", 14, None),
        pytest.param("capec", "CAPEC-185", 14, dict(capec_version="3.9")),
        pytest.param("capec", "CAPEC-185", 16, dict(capec_version="3.8")),
        pytest.param("capec", "CAPEC-185", 0, dict(capec_version=FAKE_VERSION)),
        ############# CWE #################
        pytest.param("cwe", "CWE-863", 35, None),
        pytest.param("cwe", "CWE-863", 35, dict(cwe_version="4.16")),
        pytest.param("cwe", "CWE-863", 35, dict(cwe_version="4.15")),
        pytest.param("cwe", "CWE-863", 0, dict(cwe_version=FAKE_VERSION)),
        ############## DISARM 
        pytest.param("disarm", "T0017.001", 11, None),
        pytest.param("disarm", "T0017.001", 11, dict(disarm_version='1.5')),
        pytest.param("disarm", "DISARM", 1113, dict(disarm_version='1.6')),
        pytest.param("disarm", "DISARM", 926, dict(disarm_version='1.5')),
        pytest.param("disarm", "DISARM", 0, dict(disarm_version=FAKE_VERSION)),
        ############# ATLAS #################
        pytest.param("atlas", "AML.M0000", 11, None),
        pytest.param("atlas", "AML.M0000", 11, dict(atlas_version="4.7.0")),
        pytest.param("atlas", "AML.M0000", 11, dict(atlas_version="4.5.2")),
        pytest.param("atlas", "AML.M0000", 0, dict(atlas_version=FAKE_VERSION)),
        pytest.param("atlas", "mitre-atlas", 31, dict(atlas_version="4.7.0")),
        pytest.param("atlas", "mitre-atlas", 31, dict(atlas_version="4.5.2")),
        pytest.param("atlas", "mitre-atlas", 0, dict(atlas_version=FAKE_VERSION)),
        ############ Location ###############
        pytest.param("location", "US", 11, None),
        pytest.param("location", "US", 11, dict(location_version="e19e035")),
        pytest.param("location", "US", 0, dict(location_version=FAKE_VERSION)),
        pytest.param("location", "ZA", 13, None),
        pytest.param("location", "ZA", 13, dict(location_version="e19e035")),
        pytest.param("location", "ZA", 0, dict(location_version=FAKE_VERSION)),
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
        ############## ATTACK #############
        pytest.param("attack-enterprise", "T1021.005", "2024-09-12T15:20:07.264Z", None),
        pytest.param("attack-enterprise", "T1021.005", "2024-09-12T15:20:07.264Z", dict(attack_version="16.0")),
        pytest.param("attack-enterprise", "T1021.005", "2023-05-09T14:00:00.188Z", dict(attack_version="15.1")),
        ############## CAPEC ##############
        pytest.param("capec", "CAPEC-185", "2022-09-29T00:00:00.000Z", None),
        pytest.param("capec", "CAPEC-185", "2022-09-29T00:00:00.000Z", dict(capec_version="3.9")),
        pytest.param("capec", "CAPEC-185", "2022-09-29T00:00:00.000Z", dict(capec_version="3.8")),
        ############# CWE #################
        pytest.param("cwe", "CWE-863", "2024-11-19T00:00:00.000Z", None),
        pytest.param("cwe", "CWE-863", "2024-11-19T00:00:00.000Z", dict(cwe_version="4.16")),
        pytest.param("cwe", "CWE-863", "2024-02-29T00:00:00.000Z", dict(cwe_version="4.15")),
        ############## DISARM #############
        pytest.param("disarm", "T0086.003", "2024-11-22T00:00:00.000Z", None),
        pytest.param("disarm", "T0086.003", "2024-11-22T00:00:00.000Z", dict(disarm_version="1.6")),
        pytest.param("disarm", "T0086.003", "2024-08-02T00:00:00.000Z", dict(disarm_version="1.5")),
        ############# ATLAS #################
        pytest.param("atlas", "AML.M0000", "2024-10-01T00:00:00.000Z", None),
        pytest.param("atlas", "AML.M0000", "2024-10-01T00:00:00.000Z", dict(atlas_version="4.7.0")),
        pytest.param("atlas", "AML.M0000", "2024-06-24T20:23:47.458379Z", dict(atlas_version="4.5.2")),
        ############# Location ##############
        pytest.param("location", "US", "2020-01-01T00:00:00.000Z", None),
        pytest.param("location", "US", "2020-01-01T00:00:00.000Z", dict(atlas_version="e19e035")),
        pytest.param("location", "FR", "2020-01-01T00:00:00.000Z", dict(atlas_version="e19e035")),
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

def get_all_params(params):
    paths = []
    for path, stix_id, ext_id in params:
        for path2 in ["", "relationships/", "bundle/", "versions/"]:
            if path == "atlas" and path2 == "versions/":
                #versions will be wrong for atlas because of different STIX ids per version
                continue
            paths.append((path, "{object_id}/"+path2, stix_id, ext_id))
    return paths

@pytest.mark.parametrize(
    ["path1", "path2", "stix_id", "ext_id"],
    get_all_params([
        ("atlas", "course-of-action--40076545-e797-4508-a294-943096a12111", "AML.M0000"),
        ("disarm", "attack-pattern--00dc0ed2-b16d-5f33-bad3-cc54fb7be6a9", "T0086.003"),
        ("cwe", "weakness--0ba4df3e-7815-52b7-b672-a48c56d2a286", "CWE-242"),
        ("capec", "attack-pattern--28cce7ad-5437-4fae-86b0-a21ab3a0e135", "CAPEC-699"),
        ("location", "location--e68e76c5-60f1-506e-b495-86adb8ec0a5b", "US"),
        ("attack-enterprise", "attack-pattern--01327cde-66c4-4123-bf34-5f258d59457b", "T1021.005"),
    ])
)
def test_stix_id_and_path_id_interchangability(path1, path2, stix_id, ext_id):
    url = urljoin(base_url, f"api/v1/{path1}/objects/{path2}")

    resp1 = requests.get(url.format(object_id=stix_id))
    assert resp1.status_code == 200, f"expected status_code 200, got {resp1.reason}"
    resp2 = requests.get(url.format(object_id=ext_id))
    assert resp2.status_code == 200, f"expected status_code 200, got {resp2.reason}"
    assert resp1.json() == resp2.json()