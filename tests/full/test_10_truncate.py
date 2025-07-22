import pytest


@pytest.mark.parametrize(
    "path", ["location"]
)
def test_truncate_path(client, path):
    resp = client.delete(f"/api/v1/{path}/truncate/")
    assert resp.status_code == 204, resp.content
    resp2 = client.get(f"/api/v1/{path}/objects/")
    assert resp2.status_code == 200
    assert resp2.data["total_results_count"] == 0
