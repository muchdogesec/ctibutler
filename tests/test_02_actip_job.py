


import os
from urllib.parse import urljoin

import requests

from tests.test_01_upload_bundles import TestObjectsDownload

from parameterized import parameterized, parameterized_class
@parameterized_class(
    ("mode",),
    [
        ("capec-attack",),
        ("cwe-capec",) ,
    ]
)
class TestObjectsRelate(TestObjectsDownload):
    def setUp(self):
        mode = self.mode
        self.pre_setup()
        if os.getenv('SKIP_UPLOAD'):
            return
        payload = dict()
        resp = requests.post(urljoin(self.base_url, f"api/v1/arango-cti-processor/{mode}/"), json=payload)
        print(f"{resp.request.method} {resp.url} [{payload}] => {resp.status_code} [{resp.reason}]")
        resp.raise_for_status()
        job_data = resp.json()
        self.jobs.add(job_data['id'])
        return
    

    def test_2_job_success(self):
        return self.wait_for_jobs(self)