import pytest


@pytest.mark.parametrize(
    ["include_deprecated", "include_revoked", "version", "expected_count"],
    [
        [True, True, "", 2187],
        [True, False, "", 2048],
        [False, True, "", 1918],
        [False, False, "", 1779],
        [True, True, "15.1", 2103],
        [True, False, "15.1", 1964],
        [False, True, "15.1", 1834],
        [False, False, "15.1", 1695],
    ],
)
def test_deprecated_and_revoked(
    client, include_deprecated, include_revoked, version, expected_count
):
    url = f"/api/v1/attack-enterprise/objects/"
    resp = client.get(
        url,
        query_params=dict(
            include_deprecated=include_deprecated,
            include_revoked=include_revoked,
            attack_version=version,
        ),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_results_count"] == expected_count
    for d in data["objects"]:
        if not include_revoked:
            assert d.get("revoked", False) == False
        if not include_deprecated:
            assert d.get("x_mitre_deprecated", False) == False


S1088_15_1 = {
    "description": "Techniques used by Disco (S1088)",
    "name": "S1088",
    "domain": "enterprise-attack",
    "versions": {"layer": "4.5", "attack": "15.1", "navigator": "5.1.0"},
    "techniques": [
        {
            "comment": "[Disco](https://attack.mitre.org/software/S1088) can download files to targeted systems via SMB.(Citation: MoustachedBouncer ESET August 2023)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1105",
        },
        {
            "comment": "[Disco](https://attack.mitre.org/software/S1088) has achieved initial access and execution through content injection into DNS,  HTTP, and SMB replies to targeted hosts that redirect them to download malicious files.(Citation: MoustachedBouncer ESET August 2023)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1659",
        },
        {
            "comment": "[Disco](https://attack.mitre.org/software/S1088) can create a scheduled task to run every minute for persistence.(Citation: MoustachedBouncer ESET August 2023)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1053.005",
        },
        {
            "comment": "[Disco](https://attack.mitre.org/software/S1088) has been executed through inducing user interaction with malicious .zip and .msi files.(Citation: MoustachedBouncer ESET August 2023)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1204.002",
        },
        {
            "comment": "[Disco](https://attack.mitre.org/software/S1088) can use SMB to transfer files.(Citation: MoustachedBouncer ESET August 2023)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1071.002",
        },
    ],
    "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
    "legendItems": [],
    "metadata": [
        {"name": "stix_id", "value": "malware--e1445afd-c359-45ed-8f27-626dc4d5e157"},
        {"name": "attack_id", "value": "S1088"},
    ],
    "links": [{"label": "cti_butler", "url": "https://app.ctibutler.com"}],
    "layout": {"layout": "side"},
}
S1088_16_0 = {
    "description": "Techniques used by Disco (S1088)",
    "name": "S1088",
    "domain": "enterprise-attack",
    "versions": {"layer": "4.5", "attack": "16.0", "navigator": "5.1.0"},
    "techniques": [
        {
            "comment": "[Disco](https://attack.mitre.org/software/S1088) can download files to targeted systems via SMB.(Citation: MoustachedBouncer ESET August 2023)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1105",
        },
        {
            "comment": "[Disco](https://attack.mitre.org/software/S1088) has achieved initial access and execution through content injection into DNS,  HTTP, and SMB replies to targeted hosts that redirect them to download malicious files.(Citation: MoustachedBouncer ESET August 2023)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1659",
        },
        {
            "comment": "[Disco](https://attack.mitre.org/software/S1088) can create a scheduled task to run every minute for persistence.(Citation: MoustachedBouncer ESET August 2023)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1053.005",
        },
        {
            "comment": "[Disco](https://attack.mitre.org/software/S1088) has been executed through inducing user interaction with malicious .zip and .msi files.(Citation: MoustachedBouncer ESET August 2023)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1204.002",
        },
        {
            "comment": "[Disco](https://attack.mitre.org/software/S1088) can use SMB to transfer files.(Citation: MoustachedBouncer ESET August 2023)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1071.002",
        },
    ],
    "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
    "legendItems": [],
    "metadata": [
        {"name": "stix_id", "value": "malware--e1445afd-c359-45ed-8f27-626dc4d5e157"},
        {"name": "attack_id", "value": "S1088"},
    ],
    "links": [{"label": "cti_butler", "url": "https://app.ctibutler.com"}],
    "layout": {"layout": "side"},
}
C0037_16_0 = {
    "description": "Techniques used by Water Curupira Pikabot Distribution (C0037)",
    "name": "C0037",
    "domain": "enterprise-attack",
    "versions": {"layer": "4.5", "attack": "16.0", "navigator": "5.1.0"},
    "techniques": [
        {
            "comment": "[Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) delivered [Pikabot](https://attack.mitre.org/software/S1145) installers as password-protected ZIP files containing heavily obfuscated JavaScript, or IMG files containing an LNK mimicking a Word document and a malicious DLL.(Citation: TrendMicro Pikabot 2024)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1204.002",
        },
        {
            "comment": "[Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) installation via JavaScript will launch follow-on commands via cmd.exe.(Citation: TrendMicro Pikabot 2024)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1059.003",
        },
        {
            "comment": "[Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) requires users to interact with malicious attachments in order to start [Pikabot](https://attack.mitre.org/software/S1145) installation.(Citation: TrendMicro Pikabot 2024)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1204",
        },
        {
            "comment": "[Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) used Curl.exe to download the [Pikabot](https://attack.mitre.org/software/S1145) payload from an external server, saving the file to the victim machine's temporary directory.(Citation: TrendMicro Pikabot 2024)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1105",
        },
        {
            "comment": "[Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) distributed a PDF attachment containing a malicious link to a [Pikabot](https://attack.mitre.org/software/S1145) installer.(Citation: TrendMicro Pikabot 2024)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1204.001",
        },
        {
            "comment": "[Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) utilizes thread spoofing of existing email threads in order to execute spear phishing operations.(Citation: TrendMicro Pikabot 2024)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1589.002",
        },
        {
            "comment": "[Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) attached password-protected ZIP archives to deliver [Pikabot](https://attack.mitre.org/software/S1145) installers.(Citation: TrendMicro Pikabot 2024)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1566.001",
        },
        {
            "comment": "[Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) initial delivery included obfuscated JavaScript objects stored in password-protected ZIP archives.(Citation: TrendMicro Pikabot 2024)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1059.007",
        },
        {
            "comment": "[Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) used highly obfuscated JavaScript files as one initial installer for [Pikabot](https://attack.mitre.org/software/S1145).(Citation: TrendMicro Pikabot 2024)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1140",
        },
        {
            "comment": "[Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) utilizes rundll32.exe to execute the final [Pikabot](https://attack.mitre.org/software/S1145) payload, using the named exports `Crash` or `Limit` depending on the variant.(Citation: TrendMicro Pikabot 2024)",
            "score": 100,
            "showSubtechniques": True,
            "techniqueID": "T1218.011",
        },
    ],
    "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
    "legendItems": [],
    "metadata": [
        {"name": "stix_id", "value": "campaign--57541e3b-657e-463a-a4ab-ca08d7ea9965"},
        {"name": "attack_id", "value": "C0037"},
    ],
    "links": [{"label": "cti_butler", "url": "https://app.ctibutler.com"}],
    "layout": {"layout": "side"},
}


@pytest.mark.parametrize(
    ["id", "version", "expected"],
    [
        ("malware--e1445afd-c359-45ed-8f27-626dc4d5e157", "", S1088_15_1),
        ("S1088", "16.0", S1088_16_0),
        ("S1088", "15.1", S1088_15_1),
        ("C0037", "16.0", C0037_16_0),
    ],
)
def test_navigator(client, id, version, expected):
    url = f"/api/v1/attack-enterprise/objects/{id}/navigator/"
    resp = client.get(
        url,
        query_params=dict(
            attack_version=version,
        ),
    )
    assert resp.status_code == 200
    data = resp.json()
    print(data)
    assert data == expected


@pytest.mark.parametrize(
    ["id", "version", "expected"],
    [
        ("T1021.005", "", 400),  # technique not supported
        ("T1021.005", "16.917", 404),  # not found, bad version
        ("C0037", "15.1", 404),
    ],
)
def test_navigator_fails(client, id, version, expected):
    url = f"/api/v1/attack-enterprise/objects/{id}/navigator/"
    resp = client.get(
        url,
        query_params=dict(
            attack_version=version,
        ),
    )
    assert resp.status_code == expected
