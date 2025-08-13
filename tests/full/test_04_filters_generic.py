import pytest


@pytest.mark.parametrize(
    ["path", "filters", "expected_count", "items"],
    [
        ###### ATT&CK #########
        [
            "attack-enterprise",
            dict(alias="VersaMem"),
            1,
            ["malware--0a6ec267-83a9-41a5-98c7-57c3ff81e11f"],
        ],
        [
            "attack-enterprise",
            dict(alias="versamem"),
            1,
            ["malware--0a6ec267-83a9-41a5-98c7-57c3ff81e11f"],
        ],
        [
            "attack-enterprise",
            dict(attack_id="S1154"),
            1,
            ["malware--0a6ec267-83a9-41a5-98c7-57c3ff81e11f"],
        ],
        [
            "attack-enterprise",
            dict(attack_id="s1154"),
            1,
            ["malware--0a6ec267-83a9-41a5-98c7-57c3ff81e11f"],
        ],
        [
            "attack-enterprise",
            dict(attack_id="S1154,t1558.005"),
            2,
            [
                "malware--0a6ec267-83a9-41a5-98c7-57c3ff81e11f",
                "attack-pattern--394220d9-8efc-4252-9040-664f7b115be6",
            ],
        ],
        [
            "attack-enterprise",
            dict(text="VNC"),
            8,
            {
                "attack-pattern--4061e78c-1284-44b4-9116-73e4ac3912f7",
                "attack-pattern--01327cde-66c4-4123-bf34-5f258d59457b",
                "attack-pattern--54a649ff-439a-41a4-9856-8d144a2551ba",
                "attack-pattern--b2d03cea-aec1-45ca-9744-9ee583c1e1cc",
                "attack-pattern--692074ae-bb62-4a5e-a735-02cb6bde458c",
                "attack-pattern--cbb66055-0325-4111-aca0-40547b6ad5b0",
                "attack-pattern--10d51417-ee35-4589-b1ff-b6df1c334e8d",
                "attack-pattern--09c4c11e-4fa1-4f8c-8dad-3cf8e69ad119",
            },
        ],
        [
            "attack-enterprise",
            {"text": "Malware Detect Analyze"},
            4,
            {
                "attack-pattern--d511a6f6-4a33-41d5-bc95-c343875d1377",
                "attack-pattern--e4dc8c01-417f-458d-9ee0-bb0617c1b391",
                "attack-pattern--5bfccc3f-2326-4112-86cc-c1ece9d8a2b5",
                "attack-pattern--2f41939b-54c3-41d6-8f8b-35f1ec18ed97",
            },
        ],
        [
            "attack-enterprise",
            {"text": "ransomwar sentinel"},
            7,
            {
                "malware--48d96fa0-d027-45aa-a8c3-5d09f65d596d",
                "intrusion-set--b8137919-38cb-4db0-90f3-437be885faba",
                "malware--46cbafbc-8907-42d3-9002-5327c26f8927",
                "malware--f25d4207-25b2-4bb0-a17a-403943c670ad",
                "intrusion-set--cb41e991-65f4-4668-a65f-f4200545b5a1",
                "malware--b5dc19b7-588d-403b-848d-c868bd61ffa1",
                "malware--5911d2ca-64f6-49b3-b94f-29b5d185085c",
            },
        ],
        [
            "attack-enterprise",
            dict(text="bleeping Computer inc Ransomware"),
            1,
            ["intrusion-set--cb41e991-65f4-4668-a65f-f4200545b5a1"],
        ],
        ###### CAPEC #########
        [
            "capec",
            dict(capec_id="CAPEC-701"),
            1,
            ["attack-pattern--3491dd54-d586-4f3d-80c1-9576ee48236b"],
        ],
        [
            "capec",
            dict(capec_id="capec-702"),
            1,
            ["attack-pattern--a8c03df8-2c83-493f-8e92-4c8afac0ed40"],
        ],
        [
            "capec",
            dict(id="course-of-action--49f16706-cef6-476c-902e-ca7d425a38d8"),
            1,
            ["course-of-action--49f16706-cef6-476c-902e-ca7d425a38d8"],
        ],
        [
            "capec",
            dict(
                id="course-of-action--49f16706-cef6-476c-902e-ca7d425a38d8,attack-pattern--3491dd54-d586-4f3d-80c1-9576ee48236b"
            ),
            2,
            [
                "course-of-action--49f16706-cef6-476c-902e-ca7d425a38d8",
                "attack-pattern--3491dd54-d586-4f3d-80c1-9576ee48236b",
            ],
        ],
        [
            "capec",
            dict(capec_id="capec-701,CAPEC-702"),
            2,
            [
                "attack-pattern--3491dd54-d586-4f3d-80c1-9576ee48236b",
                "attack-pattern--a8c03df8-2c83-493f-8e92-4c8afac0ed40",
            ],
        ],
        [
            "capec",
            {"text": "brute force"},
            11,
            {
                "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1",
                "attack-pattern--8c7bab16-5ecd-4778-9b04-c185bceed170",
                "attack-pattern--86a5e931-7f53-46fe-b6f0-c88498f6557f",
                "course-of-action--aba24572-8817-4d88-92bf-765eaa6ae508",
                "attack-pattern--9197c7a2-6a03-40da-b2a6-df5f1d69e8fb",
                "attack-pattern--8d88a81c-bde9-4fb3-acbe-901c783d6427",
                "attack-pattern--65737f80-588a-449a-af08-0508486d9481",
                "course-of-action--8fc9e23c-7780-4d34-8bd6-01ec3f063b9c",
                "course-of-action--8ce2fd56-5e92-4999-b81d-697c7ddb5202",
                "attack-pattern--631dcf7a-d23f-45b3-b72a-ebd5a3625aeb",
                "attack-pattern--a9dc4914-409a-4f71-80df-c5cc3923d112",
            },
        ],
        [
            "capec",
            dict(
                text="Do not provide the means for an attacker to determine success independently"
            ),
            1,
            ["course-of-action--4cce5adb-bd38-46a1-b756-9c85290ad8e7"],
        ],
        ###### CWE #########
        [
            "cwe",
            dict(cwe_id="CWe-242"),
            1,
            ["weakness--0ba4df3e-7815-52b7-b672-a48c56d2a286"],
        ],
        [
            "cwe",
            dict(cwe_id="cwe-250"),
            1,
            ["weakness--998c48c2-66cd-5735-adf7-d3ef5d975e92"],
        ],
        [
            "cwe",
            dict(
                id="weakness--0ba4df3e-7815-52b7-b672-a48c56d2a286,weakness--998c48c2-66cd-5735-adf7-d3ef5d975e92"
            ),
            2,
            [
                "weakness--0ba4df3e-7815-52b7-b672-a48c56d2a286",
                "weakness--998c48c2-66cd-5735-adf7-d3ef5d975e92",
            ],
        ],
        [
            "cwe",
            dict(cwe_id="cwe-242,cwe-250"),
            2,
            [
                "weakness--0ba4df3e-7815-52b7-b672-a48c56d2a286",
                "weakness--998c48c2-66cd-5735-adf7-d3ef5d975e92",
            ],
        ],
        [
            "cwe",
            {"text": "unnecessary privilege"},
            2,
            {
                "weakness--543176f7-7273-58c1-8962-52d5bb2e0b1a",
                "weakness--998c48c2-66cd-5735-adf7-d3ef5d975e92",
            },
        ],
        [
            "cwe",
            {"text": "LoweR PrivilEGE"},
            4,
            {
                "weakness--65e6a1f5-9776-596a-ba6f-bfc18cb4c00b",
                "weakness--1c0c0b0a-0c95-5d54-923f-c95929206d7f",
                "weakness--0755061e-b66f-5445-8303-3b5415e6675d",
                "weakness--082c9a20-e32d-5992-b981-7223a83d70a9",
            },
        ],
        ###### Location #########
        [
            "location",
            dict(alpha2_code="US"),
            1,
            ["location--e68e76c5-60f1-506e-b495-86adb8ec0a5b"],
        ],
        [
            "location",
            dict(location_id="us"),
            1,
            ["location--e68e76c5-60f1-506e-b495-86adb8ec0a5b"],
        ],
        [
            "location",
            dict(location_id="western-africa,channel-islands"),
            2,
            [
                "location--097ca10f-e203-53c0-8f9d-2634ac58bc1b",
                "location--dc791204-be18-5322-ad22-f972dd4f7f5c",
            ],
        ],
        [
            "location",
            dict(alpha3_code="usa"),
            1,
            ["location--e68e76c5-60f1-506e-b495-86adb8ec0a5b"],
        ],
        [
            "location",
            dict(alpha3_code="USA,zaf"),
            2,
            [
                "location--e68e76c5-60f1-506e-b495-86adb8ec0a5b",
                "location--23bd96f0-312a-5d26-975a-0aa1be725aaf",
            ],
        ],
        [
            "location",
            dict(
                id="location--e68e76c5-60f1-506e-b495-86adb8ec0a5b,location--23bd96f0-312a-5d26-975a-0aa1be725aaf"
            ),
            2,
            [
                "location--23bd96f0-312a-5d26-975a-0aa1be725aaf",
                "location--e68e76c5-60f1-506e-b495-86adb8ec0a5b",
            ],
        ],
        [
            "location",
            dict(location_type="intermediate-region"),
            8,
            [
                "location--097ca10f-e203-53c0-8f9d-2634ac58bc1b",
                "location--31d3ecd4-51aa-53e1-a3e6-8616093aac6b",
                "location--3c7e2d9f-a419-5c62-8cff-ba83a0e78996",
                "location--611be766-8b0b-51d0-a636-9c6ef08e0dad",
                "location--7e92c191-5824-571d-9ed3-279f30226e4e",
                "location--8cd4d00e-ce61-5fe0-af7e-c9c5daa20b21",
                "location--aff8c040-84f8-5b5b-a2a5-9166940305c2",
                "location--dc791204-be18-5322-ad22-f972dd4f7f5c",
            ],
        ],
        [
            "location",
            dict(location_type="region"),
            5,
            [
                "location--82b2b1a9-5f88-55ab-877e-812017e26fca",
                "location--99ac86ea-04aa-512c-8308-a1fd87eab9d3",
                "location--b8cdfccf-2ee8-5b4d-9e6b-46834e08bc29",
                "location--ccb963ba-9370-5eeb-80e3-c8d8738275ed",
                "location--e79cb943-c5f7-573e-a659-f24c048e8bbf",
            ],
        ],
    ],
)
def test_normal_filters(client, path, filters, expected_count, items):
    url = f"/api/v1/{path}/objects/"
    resp = client.get(url, query_params=filters)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    assert {obj["id"] for obj in data["objects"]} == set(items)


@pytest.mark.parametrize(
    ["path", "types", "expected_count"],
    [
        ["attack-enterprise", ("attack-pattern",), 656],
        ["attack-enterprise", ("tool",), 88],
        ["attack-enterprise", ("attack-pattern", "tool"), 88 + 656],
        ["attack-enterprise", ("x-mitre-data-component",), 106],
        ["attack-enterprise", ("x-mitre-tactic",), 14],
        ["attack-enterprise", ("course-of-action",), 44],
        ["attack-enterprise", ("intrusion-set",), 160],
        [
            "attack-enterprise",
            (
                "x-mitre-tactic",
                "x-mitre-data-component",
                "course-of-action",
                "intrusion-set",
            ),
            14 + 106 + 44 + 160,
        ],
        ["attack-enterprise", ("fake-type",), 0],
    ],
)
def test_filter_type(client, path, types, expected_count):
    url = f"/api/v1/{path}/objects/"
    resp = client.get(url, query_params=dict(types=",".join(types)))
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    assert set(obj["type"] for obj in data["objects"]).issubset(
        types
    ), "found unexpected types in response objects"


@pytest.mark.parametrize(
    ["path", "group_type", "expected_count"],
    [
        ######### ATT&CK ###########
        ["attack-enterprise", "Tactic", 14],
        ["attack-enterprise", "Technique", 203],
        ["attack-enterprise", "Sub-technique", 453],
        ["attack-enterprise", "Mitigation", 44],
        ["attack-enterprise", "Group", 160],
        ["attack-enterprise", "Software", 711],
        ["attack-enterprise", "Campaign", 34],
        ["attack-enterprise", "Data Source", 37],
        ["attack-enterprise", "Data Component", 106],
        ["attack-enterprise", "Asset", 0],
        ######### DISARM ###########
        ["disarm", "Tactic", 16],
        ["disarm", "Technique", 103],
        ["disarm", "Sub-technique", 288],
    ],
)
def test_group_filter(client, path, group_type, expected_count):
    type_map = {
        "Tactic": "x-mitre-tactic",
        "Group": "intrusion-set",
        "Mitigation": "course-of-action",
        "Campaign": "campaign",
        "Data Source": "x-mitre-data-source",
        "Data Component": "x-mitre-data-component",
        "Asset": "x-mitre-asset",
    }

    url = f"/api/v1/{path}/objects/"

    param_name = path.split("-")[0] + "_type"  # disarm_type or attack_type
    resp = client.get(url, query_params={param_name: group_type})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    for obj in data["objects"]:
        match group_type:
            case "Technique":
                assert obj["type"] == "attack-pattern"
                assert (
                    obj.get("x_mitre_is_subtechnique", False) != True
                ), "x_mitre_is_subtechnique must be False or NULL for techinque"
            case "Sub-technique":
                assert obj["type"] == "attack-pattern"
                assert (
                    obj.get("x_mitre_is_subtechnique", False) == True
                ), "x_mitre_is_subtechnique must be True for sub-techinque"
            case "Software":
                assert obj["type"] in ["malware", "tool"]
            case _:
                assert obj["type"] == type_map[group_type]


@pytest.mark.parametrize(
    ["path", "search_text", "expected_count"],
    [
        ["attack-enterprise", "privilege", 132],
        ["cwe", "privilege", 77],
        ["capec", "fronting", 6],
        ["atlas", "Account", 7],
        ["disarm", "Account", 79],
    ],
)
def test_description_filter(client, path, search_text, expected_count):
    url = f"/api/v1/{path}/objects/"
    resp = client.get(url, query_params=dict(text=search_text))
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
