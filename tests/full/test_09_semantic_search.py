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


@pytest.mark.parametrize(
    "knowledge_bases,expected_count",
    [
        [[], 112],
        [['attack-ics'], 0], #not ingested
        [['attack-enterprise'], 66],
        [['attack'], 66],
        [['attack', 'attack-ics'], 66],
        [['location', 'attack'], 66],
        [['location', 'cwe'], 14],
        [['capec'], 25],
        [['disarm'], 7],
        [['disarm', 'capec'], 7+25],
    ],
)
def test_search_with_knowledge_bases(client, knowledge_bases, expected_count):
    resp = client.get("/api/v1/search/?text=deny&knowledge_bases="+",".join(knowledge_bases))
    assert resp.data["total_results_count"] == expected_count


def test_search_with_show_knowledgebase(client):
    resp1 = client.get("/api/v1/search/?text=deny&show_knowledgebase=true")
    assert all(map(lambda x: "knowledgebase_name" in x, resp1.data["objects"]))


    resp2 = client.get("/api/v1/search/?text=deny&show_knowledgebase=false")
    assert all(map(lambda x: "knowledgebase_name" not in x, resp2.data["objects"]))


    resp3 = client.get("/api/v1/search/?text=deny")
    assert all(map(lambda x: "knowledgebase_name" not in x, resp3.data["objects"]))

    assert resp1.data["total_results_count"] == resp2.data["total_results_count"]
    assert resp3.data["total_results_count"] == resp2.data["total_results_count"]

