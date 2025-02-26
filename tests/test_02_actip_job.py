


import os
from urllib.parse import urljoin

import requests

from tests.test_01_upload_bundles import TestObjectsDownload

ACTIP_MODES = [
    "capec-attack",
    "cwe-capec"
]

class TestObjectsRelate(TestObjectsDownload):
    def setUp(self):
        self.base_url = os.environ['CTIBUTLER_URL']
        for mode in ACTIP_MODES:
            payload = dict()
            resp = requests.post(urljoin(self.base_url, f"api/v1/arango-cti-processor/{mode}/"), json=payload)
            print(f"{resp.request.method} {resp.url} [{payload}] => {resp.status_code} [{resp.reason}]")
            resp.raise_for_status()
            job_data = resp.json()
            self.jobs.add(job_data['id'])
        return