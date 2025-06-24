import os
import random
import time
from types import SimpleNamespace
import unittest, pytest
from urllib.parse import urljoin


@pytest.mark.parametrize(
    "endpoint",
    [
        "smos",
        "sros",
        "scos",
        "sdos",
    ],
)
def test_paths_no_dup(client, endpoint):
    url = f"/api/v1/objects/{endpoint}/"
    resp = client.get(url)
    assert resp.status_code == 200, url
    data = resp.json()
    assert data["page_results_count"] <= data["total_results_count"]
    object_refs = {obj["id"] for obj in data["objects"]}
    dd = [obj["id"] for obj in data["objects"]]
    for d in object_refs:
        dd.remove(d)
    assert (
        len(object_refs) == data["page_results_count"]
    ), f"data contains duplicate ids"


@pytest.mark.parametrize(
    "object_id",
    [
        "location--e68e76c5-60f1-506e-b495-86adb8ec0a5b",
        "weakness--0755061e-b66f-5445-8303-3b5415e6675d",
        "attack-pattern--65737f80-588a-449a-af08-0508486d9481",
        "malware--f25d4207-25b2-4bb0-a17a-403943c670ad",
        "attack-pattern--01327cde-66c4-4123-bf34-5f258d59457b",
    ],
)
def test_object_retrieve(client, object_id):
    url = f"/api/v1/objects/{object_id}/"
    resp = client.get(url)
    assert resp.status_code == 200, url
    data = resp.json()
    assert data["total_results_count"] == 1, "object must return only 1 object"
    assert data["objects"][0]["id"] == object_id, "unexpected stix object id"
