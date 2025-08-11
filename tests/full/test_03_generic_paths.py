import pytest

from ctibutler.server import models


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
        pytest.param("atlas", 158, None),
        pytest.param("atlas", 158, dict(atlas_version="4.9.0")),
        pytest.param("atlas", 0, dict(atlas_version=FAKE_VERSION)),
        ######## Location #######
        pytest.param("location", 279, None),
        pytest.param("location", 279, dict(location_version="1.0")),
        pytest.param("location", 0, dict(location_version=FAKE_VERSION)),
    ],
)
def test_path_objects_count(client, path, expected_result_count, params):
    resp = client.get(f"/api/v1/{path}/objects/", query_params=params)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_result_count
    ## check uniqueness of objects by id
    assert (
        len({x["id"] for x in data["objects"]}) == data["page_results_count"]
    ), "response contains duplicates"


@pytest.mark.parametrize(
    ["path", "expected_versions"],
    [
        pytest.param("capec", ["3.9", "3.8"]),
        pytest.param("attack-enterprise", ["16.0", "15.1"]),
        pytest.param("atlas", ["4.9.0"]),
        pytest.param("cwe", ["4.16", "4.15"]),
        pytest.param("location", ["1.0"]),
        pytest.param("disarm", ["1.6", "1.5"]),
    ],
)
def test_path_versions(client, path, expected_versions):
    resp = client.get(f"/api/v1/{path}/versions/installed/")
    assert resp.status_code == 200
    versions = tuple(resp.json()["versions"])
    assert versions == tuple(expected_versions)


    resp2 = client.get(f"/api/v1/{path}/versions/available/")
    assert resp2.status_code == 200
    versions = set(resp2.json())
    assert versions.issuperset(expected_versions)


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
                {"modified": "2025-04-22T21:54:36.102749Z", "versions": ["4.9.0"]},
            ],
        ),
        pytest.param(
            "location",
            "US",
            [{"modified": "2020-01-01T00:00:00.000Z", "versions": ["1.0"]}],
        ),
    ],
)
def test_object_versions(client, path, object_id, expected_versions):
    resp = client.get(f"/api/v1/{path}/objects/{object_id}/versions/")
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
        pytest.param(
            "attack-enterprise", "T1021.005", 0, dict(attack_version=FAKE_VERSION)
        ),
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
        pytest.param("disarm", "T0017.001", 11, dict(disarm_version="1.5")),
        pytest.param("disarm", "DISARM", 1401, dict(disarm_version="1.6")),
        pytest.param("disarm", "DISARM", 1151, dict(disarm_version="1.5")),
        pytest.param("disarm", "DISARM", 0, dict(disarm_version=FAKE_VERSION)),
        ############# ATLAS #################
        pytest.param("atlas", "AML.M0000", 11, None),
        pytest.param("atlas", "AML.M0000", 11, dict(atlas_version="4.9.0")),
        pytest.param("atlas", "AML.M0000", 0, dict(atlas_version=FAKE_VERSION)),
        pytest.param("atlas", "mitre-atlas", 33, dict(atlas_version="4.9.0")),
        pytest.param("atlas", "mitre-atlas", 0, dict(atlas_version=FAKE_VERSION)),
        ############ Location ###############
        pytest.param("location", "US", 11, None),
        pytest.param("location", "US", 11, dict(location_version="1.0")),
        pytest.param("location", "US", 0, dict(location_version=FAKE_VERSION)),
        pytest.param("location", "ZA", 13, None),
        pytest.param("location", "ZA", 13, dict(location_version="1.0")),
        pytest.param("location", "ZA", 0, dict(location_version=FAKE_VERSION)),
    ],
)
def test_object_count_bundle(client, path, object_id, expected_count, params):
    url = f"/api/v1/{path}/objects/{object_id}/bundle/"
    resp = client.get(url, query_params=params)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    ## check uniqueness of objects by id
    assert (
        len({x["id"] for x in data["objects"]}) == data["page_results_count"]
    ), "response contains duplicates"


@pytest.mark.parametrize(
    ["path", "object_id", "expected_modified", "params"],
    [
        ############## ATTACK #############
        pytest.param(
            "attack-enterprise", "T1021.005", "2024-09-12T15:20:07.264Z", None
        ),
        pytest.param(
            "attack-enterprise",
            "T1021.005",
            "2024-09-12T15:20:07.264Z",
            dict(attack_version="16.0"),
        ),
        pytest.param(
            "attack-enterprise",
            "T1021.005",
            "2023-05-09T14:00:00.188Z",
            dict(attack_version="15.1"),
        ),
        ############## CAPEC ##############
        pytest.param("capec", "CAPEC-185", "2022-09-29T00:00:00.000Z", None),
        pytest.param(
            "capec", "CAPEC-185", "2022-09-29T00:00:00.000Z", dict(capec_version="3.9")
        ),
        pytest.param(
            "capec", "CAPEC-185", "2022-09-29T00:00:00.000Z", dict(capec_version="3.8")
        ),
        ############# CWE #################
        pytest.param("cwe", "CWE-863", "2024-11-19T00:00:00.000Z", None),
        pytest.param(
            "cwe", "CWE-863", "2024-11-19T00:00:00.000Z", dict(cwe_version="4.16")
        ),
        pytest.param(
            "cwe", "CWE-863", "2024-02-29T00:00:00.000Z", dict(cwe_version="4.15")
        ),
        ############## DISARM #############
        pytest.param("disarm", "T0086.003", "2024-11-22T00:00:00.000Z", None),
        pytest.param(
            "disarm",
            "T0086.003",
            "2024-11-22T00:00:00.000Z",
            dict(disarm_version="1.6"),
        ),
        pytest.param(
            "disarm",
            "T0086.003",
            "2024-08-02T00:00:00.000Z",
            dict(disarm_version="1.5"),
        ),
        ############# ATLAS #################
        pytest.param("atlas", "AML.M0000", "2025-04-22T21:54:36.102205Z", None),
        pytest.param(
            "atlas",
            "AML.M0000",
            "2025-04-22T21:54:36.102205Z",
            dict(atlas_version="4.9.0"),
        ),
        ############# Location ##############
        pytest.param("location", "US", "2020-01-01T00:00:00.000Z", None),
        pytest.param(
            "location", "US", "2020-01-01T00:00:00.000Z", dict(atlas_version="1.0")
        ),
        pytest.param(
            "location", "FR", "2020-01-01T00:00:00.000Z", dict(atlas_version="1.0")
        ),
    ],
)
def test_object_modified(client, path, object_id, expected_modified, params):
    url = f"/api/v1/{path}/objects/{object_id}/"
    resp = client.get(url, query_params=params)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["objects"]) == 1
    assert data["objects"][0]["modified"] == expected_modified


@pytest.mark.parametrize(
    ["path", "object_id", "expected_count", "params"],
    [
        pytest.param("capec", "CAPEC-185", 8, None),
        pytest.param(
            "capec", "CAPEC-185", 5, dict(relationship_direction="source_ref")
        ),
        pytest.param("capec", "CAPEC-185", 8, dict(capec_version="3.9")),
        pytest.param("capec", "CAPEC-185", 9, dict(capec_version="3.8")),
        pytest.param(
            "capec",
            "CAPEC-185",
            4,
            dict(capec_version="3.8", relationship_direction="target_ref"),
        ),
        ##############
        pytest.param("disarm", "T0086.003", 5, None),
        pytest.param("disarm", "T0086.003", 5, dict(disarm_version="1.5")),
    ],
)
def test_object_count_relationships(client, path, object_id, expected_count, params):
    url = f"/api/v1/{path}/objects/{object_id}/relationships/"
    resp = client.get(url, query_params=params)
    assert resp.status_code == 200, f"expected status_code 200, got {resp.reason}"
    data = resp.json()
    assert data["total_results_count"] == expected_count
    ## check uniqueness of objects by id
    assert (
        len({x["id"] for x in data["relationships"]}) == data["page_results_count"]
    ), "response contains duplicates"


def get_all_params(params):
    paths = []
    for path, stix_id, ext_id in params:
        for path2 in ["", "relationships/", "bundle/", "versions/"]:
            if path == "atlas" and path2 == "versions/":
                # versions will be wrong for atlas because of different STIX ids per version
                continue
            paths.append((path, "{object_id}/" + path2, stix_id, ext_id))
    return paths


@pytest.mark.parametrize(
    ["path1", "path2", "stix_id", "ext_id"],
    get_all_params(
        [
            (
                "atlas",
                "course-of-action--c2885145-a7d5-4100-983d-4d6de9f26425",
                "AML.M0000",
            ),
            (
                "disarm",
                "attack-pattern--00dc0ed2-b16d-5f33-bad3-cc54fb7be6a9",
                "T0086.003",
            ),
            ("cwe", "weakness--0ba4df3e-7815-52b7-b672-a48c56d2a286", "CWE-242"),
            (
                "capec",
                "attack-pattern--28cce7ad-5437-4fae-86b0-a21ab3a0e135",
                "CAPEC-699",
            ),
            ("location", "location--e68e76c5-60f1-506e-b495-86adb8ec0a5b", "US"),
            (
                "attack-enterprise",
                "attack-pattern--01327cde-66c4-4123-bf34-5f258d59457b",
                "T1021.005",
            ),
        ]
    ),
)
def test_stix_id_and_path_id_interchangability(client, path1, path2, stix_id, ext_id):
    url = f"/api/v1/{path1}/objects/{path2}"

    resp1 = client.get(url.format(object_id=stix_id))
    assert resp1.status_code == 200, f"expected status_code 200, got {resp1.reason}"
    resp2 = client.get(url.format(object_id=ext_id))
    assert resp2.status_code == 200, f"expected status_code 200, got {resp2.reason}"
    assert resp1.json() == resp2.json()

@pytest.mark.django_db
@pytest.mark.parametrize(
    'types,count',
    [
        ('', 3),
        ('disarm-update', 0),
        ('attack-update', 1),
        ('attack-update--mobile', 0),
        ('attack-update--enterprise', 1),
        ('arango-cti-processor', 1),
        ('arango-cti-processor,disarm-update', 1),
        ('arango-cti-processor,disarm-update,attack-update', 2),
    ]
)
def test_jobs(client, types, count):
    job1 = models.Job.objects.create(type=models.JobType.ATLAS_UPDATE, parameters={})
    job2 = models.Job.objects.create(type=models.JobType.CTI_PROCESSOR, parameters={})
    job3 = models.Job.objects.create(type=models.JobType.ATTACK_UPDATE, parameters={'mode': 'enterprise'})

    assert client.get('/api/v1/jobs/', query_params=dict(types=types)).data['total_results_count'] == count

def test_schema(client):
    assert client.get('/api/schema/').status_code == 200