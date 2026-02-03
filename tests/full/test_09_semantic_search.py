import pytest


def test_search_no_query(client):
    resp = client.get("/api/v1/search/?types=attack-pattern")
    assert resp.status_code == 200
    assert resp.data['total_results_count'] > 20


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
        [[], 77],
        [['attack-ics'], 8],
        [['attack-mobile'], 0], #not ingested
        [['attack-enterprise'], 13],
        [['attack'], 21],
        [['attack', 'attack-ics'], 21],
        [['attack-ics', 'attack-mobile'], 8],
        [['location', 'attack'], 21],
        [['location', 'cwe'], 7],
        [['capec'], 25],
        [['disarm'], 7],
        [['disarm', 'capec'], 7+25],
        [["d3fend"], 17],
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

@pytest.mark.parametrize(
    ['filters', 'count'],
    [
        pytest.param(dict(include_deprecated=False, include_revoked=False), 7031, id='exclude-both-explicit'),
        pytest.param(dict(), 7031, id='exclude-both-implicit'),
        pytest.param(dict(include_deprecated=True, include_revoked=False), 7377, id='include-deprecated-explicit'),
        pytest.param(dict(include_deprecated=True), 7377, id='exclude-revoked-implicit'),
        pytest.param(dict(include_deprecated=False, include_revoked=True), 7197, id='include-revoked-explicit'),
        pytest.param(dict(include_revoked=True), 7197, id='exlude-deprecated-implicit'),
        pytest.param(dict(include_deprecated=True, include_revoked=True), 7543, id='include-both-explicit'),
        pytest.param(dict(knowledge_bases='capec'), 1452, id='capec-implicit-exclude-deprecated'),
        pytest.param(dict(knowledge_bases='capec', include_deprecated=False), 1452, id='capec-exclude-deprecated-explicit'),
        pytest.param(dict(knowledge_bases='capec', include_deprecated=True), 1509, id='capec-include-deprecated-explicit'),
        pytest.param(dict(knowledge_bases='sector'), 85, id='capec-include-deprecated-explicit'),
        pytest.param(dict(knowledge_bases='d3fend', include_deprecated=False), 1162, id='d3fend-exclude-deprecated-explicit'), # d3fend does not contain revoked objects
        pytest.param(dict(knowledge_bases='d3fend', include_deprecated=True), 1162, id='d3fend-include-deprecated-explicit'),
    ]
)
def test_include_revoked_and_include_deprecated(client, filters, count):
    params = {}
    params.update(filters)
    resp = client.get("/api/v1/search/", query_params=params)
    assert resp.status_code == 200
    assert resp.data['total_results_count'] == count