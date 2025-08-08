

def test_tie_bad_techniques(client):
    resp = client.get('/api/v1/attack-enterprise/tie/?technique_ids=T1001,Tbad01')
    assert resp.status_code == 400


def test_tie_good_techniques(client):
    resp = client.get('/api/v1/attack-enterprise/tie/?technique_ids=T1001')
    assert resp.status_code == 200
