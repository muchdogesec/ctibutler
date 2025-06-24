import pytest

import unicodedata


def remove_accents(input_str):
    if not isinstance(input_str, str):
        return input_str
    nfkd_form = unicodedata.normalize("NFKD", input_str)
    only_ascii = nfkd_form.encode("ASCII", "ignore")
    return only_ascii.decode().lower()


@pytest.mark.parametrize(
    ["path", "sort_key"],
    [
        ["attack-enterprise", "created"],
        ["attack-enterprise", "modified"],
        ["capec", "created"],
        ["capec", "modified"],
        ["cwe", "created"],
        ["cwe", "modified"],
        ["location", "name"],
        ["cwe", "created"],
        ["cwe", "modified"],
        ["atlas", "created"],
        ["atlas", "modified"],
        ["disarm", "created"],
        ["disarm", "modified"],
    ],
)
def test_sort_algo(client, path, sort_key):
    url = f"/api/v1/{path}/objects/"
    resp_asc = client.get(url, query_params=dict(sort=f"{sort_key}_ascending"))
    assert resp_asc.status_code == 200
    data_asc = resp_asc.json()

    url = f"/api/v1/{path}/objects/"
    resp_desc = client.get(url, query_params=dict(sort=f"{sort_key}_descending"))
    assert resp_desc.status_code == 200
    data_desc = resp_desc.json()

    assert (
        data_desc["total_results_count"] == data_asc["total_results_count"]
    ), "sort ascending and sort descending must have same result count"

    previous_point = None
    for d in data_asc["objects"]:
        current_point = d.get(sort_key)
        if not previous_point:
            previous_point = current_point
            continue
        if not current_point:
            continue
        assert remove_accents(current_point) >= remove_accents(
            previous_point
        ), "expected data to be sorted in ascending order"
        previous_point = current_point

    previous_point = None
    for d in data_desc["objects"]:
        current_point = d.get(sort_key)
        if not previous_point:
            previous_point = current_point
            continue
        if not current_point:
            continue
        assert remove_accents(current_point) <= remove_accents(
            previous_point
        ), "expected data to be sorted in descending order"
        previous_point = current_point
