import pytest


path_versions_1 = [
    ("/api/v1/location/", "e19e035"),
    ("/api/v1/disarm/", "1_6"),
    ("/api/v1/atlas/", "4_9_0"),
    ("/api/v1/attack-enterprise/", "16_0"),
    ("/api/v1/cwe/", "4_16"),
    ("/api/v1/capec/", "3_9"),
]

path_versions_2 = [
    ("/api/v1/attack-enterprise/", "15_1"),
    ("/api/v1/cwe/", "4_15"),
    ("/api/v1/capec/", "3_8"),
    ("/api/v1/disarm/", "1_5"),
]


@pytest.mark.django_db
@pytest.mark.parametrize("path,version", path_versions_1 + path_versions_2)
def test_make_upload(client, eager_celery, path, version):
    payload = dict(version=version)
    resp = client.post(path, data=payload, content_type="application/json")
    assert resp.status_code == 201
    job_data = resp.json()
    job_id = job_data["id"]
    job_resp = client.get(f"/api/v1/jobs/{job_id}/")
    assert job_resp.status_code == 200
    assert job_resp.data["state"] == "completed"


@pytest.mark.parametrize(
    "mode",
    [
        "capec-attack",
        "cwe-capec",
    ],
)
@pytest.mark.django_db
def test_acvep_run(client, eager_celery, mode):
    resp = client.post(f"/api/v1/arango-cti-processor/{mode}/")
    assert resp.status_code == 201
    job_data = resp.json()
    job_id = job_data["id"]
    job_resp = client.get(f"/api/v1/jobs/{job_id}/")
    assert job_resp.status_code == 200
    assert job_resp.data["state"] == "completed"
