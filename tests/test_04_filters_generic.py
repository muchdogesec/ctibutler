import pytest
import os
from urllib.parse import urljoin
import pytest
import requests

base_url = os.environ["CTIBUTLER_URL"]

@pytest.mark.parametrize(
    ["path", "filters", "expected_count", "items"],
    [
        ###### ATT&CK #########
        ["attack-enterprise", dict(alias="VersaMem"), 1, ["malware--0a6ec267-83a9-41a5-98c7-57c3ff81e11f"]],
        ["attack-enterprise", dict(alias="versamem"), 1, ["malware--0a6ec267-83a9-41a5-98c7-57c3ff81e11f"]],
        ["attack-enterprise", dict(attack_id="S1154"), 1, ["malware--0a6ec267-83a9-41a5-98c7-57c3ff81e11f"]],
        ["attack-enterprise", dict(attack_id="s1154"), 1, ["malware--0a6ec267-83a9-41a5-98c7-57c3ff81e11f"]],
        ["attack-enterprise", dict(attack_id="S1154,t1558.005"), 2, ["malware--0a6ec267-83a9-41a5-98c7-57c3ff81e11f", "attack-pattern--394220d9-8efc-4252-9040-664f7b115be6"]],
        ["attack-enterprise", dict(name="VNC"), 1, ["attack-pattern--01327cde-66c4-4123-bf34-5f258d59457b"]],
        ["attack-enterprise", dict(name="vnc"), 1, ["attack-pattern--01327cde-66c4-4123-bf34-5f258d59457b"]],
        ["attack-enterprise", dict(name="INC Ransomware"), 1, ["malware--f25d4207-25b2-4bb0-a17a-403943c670ad"]],
        ["attack-enterprise", dict(name="c ransomw"), 1, ["malware--f25d4207-25b2-4bb0-a17a-403943c670ad"]],
        ["attack-enterprise", dict(description="bleeping Computer inc Ransomware"), 1, ["intrusion-set--cb41e991-65f4-4668-a65f-f4200545b5a1"]],
        ###### CAPEC #########
        ["capec", dict(capec_id="CAPEC-701"), 1, ["attack-pattern--3491dd54-d586-4f3d-80c1-9576ee48236b"]],
        ["capec", dict(capec_id="capec-702"), 1, ["attack-pattern--a8c03df8-2c83-493f-8e92-4c8afac0ed40"]],
        ["capec", dict(id="course-of-action--49f16706-cef6-476c-902e-ca7d425a38d8"), 1, ["course-of-action--49f16706-cef6-476c-902e-ca7d425a38d8"]],
        ["capec", dict(id="course-of-action--49f16706-cef6-476c-902e-ca7d425a38d8,attack-pattern--3491dd54-d586-4f3d-80c1-9576ee48236b"), 2, ["course-of-action--49f16706-cef6-476c-902e-ca7d425a38d8", "attack-pattern--3491dd54-d586-4f3d-80c1-9576ee48236b"]],
        ["capec", dict(capec_id="capec-701,CAPEC-702"), 2, ["attack-pattern--3491dd54-d586-4f3d-80c1-9576ee48236b", "attack-pattern--a8c03df8-2c83-493f-8e92-4c8afac0ed40"]],
        ["capec", dict(name="brute force"), 2, ["attack-pattern--65737f80-588a-449a-af08-0508486d9481", "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"]],
        ["capec", dict(description="Do not provide the means for an attacker to determine success independently"), 1, ["course-of-action--4cce5adb-bd38-46a1-b756-9c85290ad8e7"]],
        ###### CWE #########
        ["cwe", dict(cwe_id="CWe-242"), 1, ["weakness--0ba4df3e-7815-52b7-b672-a48c56d2a286"]],
        ["cwe", dict(cwe_id="cwe-250"), 1, ["weakness--998c48c2-66cd-5735-adf7-d3ef5d975e92"]],
        ["cwe", dict(id="weakness--0ba4df3e-7815-52b7-b672-a48c56d2a286,weakness--998c48c2-66cd-5735-adf7-d3ef5d975e92"), 2, ["weakness--0ba4df3e-7815-52b7-b672-a48c56d2a286", "weakness--998c48c2-66cd-5735-adf7-d3ef5d975e92"]],
        ["cwe", dict(cwe_id="cwe-242,cwe-250"), 2, ["weakness--0ba4df3e-7815-52b7-b672-a48c56d2a286", "weakness--998c48c2-66cd-5735-adf7-d3ef5d975e92"]],
        ["cwe", dict(name="unnecessary privilege"), 1, ["weakness--998c48c2-66cd-5735-adf7-d3ef5d975e92"]],
        ["cwe", dict(description="LoweR PrivilEGE"), 1, ["weakness--0755061e-b66f-5445-8303-3b5415e6675d"]],
        ###### Location #########
        ["location", dict(alpha2_code="US"), 1, ["location--e68e76c5-60f1-506e-b495-86adb8ec0a5b"]],
        ["location", dict(location_id="us"), 1, ["location--e68e76c5-60f1-506e-b495-86adb8ec0a5b"]],
        ["location", dict(location_id="western-africa,channel-islands"), 2, ["location--097ca10f-e203-53c0-8f9d-2634ac58bc1b", "location--dc791204-be18-5322-ad22-f972dd4f7f5c"]],
        ["location", dict(alpha3_code="usa"), 1, ["location--e68e76c5-60f1-506e-b495-86adb8ec0a5b"]],
        ["location", dict(alpha3_code="USA,zaf"), 2, ["location--e68e76c5-60f1-506e-b495-86adb8ec0a5b", "location--23bd96f0-312a-5d26-975a-0aa1be725aaf"]],
        ["location", dict(id="location--e68e76c5-60f1-506e-b495-86adb8ec0a5b,location--23bd96f0-312a-5d26-975a-0aa1be725aaf"), 2, ["location--23bd96f0-312a-5d26-975a-0aa1be725aaf", "location--e68e76c5-60f1-506e-b495-86adb8ec0a5b"]],
        ["location", dict(location_type="intermediate-region"), 8, ['location--097ca10f-e203-53c0-8f9d-2634ac58bc1b', 'location--31d3ecd4-51aa-53e1-a3e6-8616093aac6b', 'location--3c7e2d9f-a419-5c62-8cff-ba83a0e78996', 'location--611be766-8b0b-51d0-a636-9c6ef08e0dad', 'location--7e92c191-5824-571d-9ed3-279f30226e4e', 'location--8cd4d00e-ce61-5fe0-af7e-c9c5daa20b21', 'location--aff8c040-84f8-5b5b-a2a5-9166940305c2', 'location--dc791204-be18-5322-ad22-f972dd4f7f5c']],
        ["location", dict(location_type="region"), 5, ['location--82b2b1a9-5f88-55ab-877e-812017e26fca', 'location--99ac86ea-04aa-512c-8308-a1fd87eab9d3', 'location--b8cdfccf-2ee8-5b4d-9e6b-46834e08bc29', 'location--ccb963ba-9370-5eeb-80e3-c8d8738275ed', 'location--e79cb943-c5f7-573e-a659-f24c048e8bbf']],

    ]
)
def test_normal_filters(path, filters, expected_count, items):
    url = urljoin(base_url, f"api/v1/{path}/objects/")
    resp = requests.get(url, params=filters)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    assert {obj['id'] for obj in data['objects']} == set(items)

@pytest.mark.parametrize(
        ["path", "types", "expected_count"],
        [
            ["attack-enterprise", ("attack-pattern",), 656 ],
            ["attack-enterprise", ("tool",), 88 ],
            ["attack-enterprise", ("attack-pattern", "tool"), 88+656 ],

            ["attack-enterprise", ("x-mitre-data-component",), 106 ],
            ["attack-enterprise", ("x-mitre-tactic",), 14 ],
            ["attack-enterprise", ("course-of-action",), 44 ],
            ["attack-enterprise", ("intrusion-set",), 160 ],
            ["attack-enterprise", ("x-mitre-tactic", "x-mitre-data-component", "course-of-action", "intrusion-set"), 14+106+44+160 ],
            ["attack-enterprise", ("fake-type", ), 0 ],
        ]
)
def test_filter_type(path, types, expected_count):
    url = urljoin(base_url, f"api/v1/{path}/objects/")
    resp = requests.get(url, params=dict(types=",".join(types)))
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    assert set(obj['type'] for obj in data['objects']).issubset(types), "found unexpected types in response objects"



@pytest.mark.parametrize(
        ["path", "group_type", "expected_count"],
        [
            ######### ATT&CK ###########
            ["attack-enterprise", "Tactic", 14 ],
            ["attack-enterprise", "Technique", 203 ],
            ["attack-enterprise", "Sub-technique", 453 ],
            ["attack-enterprise", "Mitigation", 44 ],
            ["attack-enterprise", "Group", 160 ],
            ["attack-enterprise", "Software", 711 ],
            ["attack-enterprise", "Campaign", 34 ],
            ["attack-enterprise", "Data Source", 37 ],
            ["attack-enterprise", "Data Component", 106 ],
            ["attack-enterprise", "Asset", 0 ],
            ######### DISARM ###########
            ["disarm", "Tactic", 16 ],
            ["disarm", "Technique", 103 ],
            ["disarm", "Sub-technique", 288 ],
        ]
)
def test_group_filter(path, group_type, expected_count):
    type_map = {
        "Tactic": "x-mitre-tactic",
        "Group": "intrusion-set",
        "Mitigation": 'course-of-action',
        "Campaign": 'campaign',
        "Data Source": 'x-mitre-data-source',
        "Data Component": 'x-mitre-data-component',
        "Asset": 'x-mitre-asset',
    }

    url = urljoin(base_url, f"api/v1/{path}/objects/")
    
    param_name = path.split('-')[0]+'_type' #disarm_type or attack_type
    resp = requests.get(url, params={param_name: group_type})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    for obj in data['objects']:
        match group_type:
            case "Technique":
                assert obj['type'] == "attack-pattern"
                assert obj.get("x_mitre_is_subtechnique", False) != True, "x_mitre_is_subtechnique must be False or NULL for techinque"
            case "Sub-technique":
                assert obj['type'] == "attack-pattern"
                assert obj.get("x_mitre_is_subtechnique", False) == True, "x_mitre_is_subtechnique must be True for sub-techinque"
            case "Software":
                assert obj["type"] in ["malware", "tool"]
            case _:
                assert obj['type'] == type_map[group_type]

@pytest.mark.parametrize(
        ["path", "name", "expected_count"],
        [
            ["attack-enterprise", "privilege", 4],
            ["cwe", "privilege", 16],
            ["capec", "privilege", 8],
            ["atlas", "Account", 2],
            ["location", "nigeria", 1],
            ["disarm", "Account", 18],
        ]
)
def test_name_filter(path, name, expected_count):
    url = urljoin(base_url, f"api/v1/{path}/objects/")
    resp = requests.get(url, params=dict(name=name))
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    for obj in data['objects']:
        assert name.lower() in obj['name'].lower()


@pytest.mark.parametrize(
        ["path", "description", "expected_count"],
        [
            ["attack-enterprise", "privilege", 133],
            ["cwe", "privilege", 78],
            ["capec", "privilege", 94],
            ["atlas", "Account", 7],
            ["disarm", "Account", 79],
        ]
)
def test_description_filter(path, description, expected_count):
    url = urljoin(base_url, f"api/v1/{path}/objects/")
    resp = requests.get(url, params=dict(description=description))
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    for obj in data['objects']:
        assert description.lower() in obj['description'].lower()
