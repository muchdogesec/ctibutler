import pytest


def test_search_no_query(client):
    resp = client.get("/api/v1/search/?types=sometype")
    assert resp.status_code == 400


def test_search_with_query(client):
    resp = client.get("/api/v1/search/?text=deny+service")
    assert resp.data["total_results_count"] >= 20


@pytest.mark.parametrize(
    "types",
    [
        ("attack-pattern", "course-of-action"),
        ("course-of-action",),
        ("attack-pattern",),
    ],
)
def test_search_with_types(client, types):
    resp = client.get("/api/v1/search/?text=deny+service&types=" + ",".join(types))
    assert {obj["type"] for obj in resp.data["objects"]} == set(types)
