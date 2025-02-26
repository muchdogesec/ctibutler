import os
import time
import unittest
from urllib.parse import urljoin

import requests
from parameterized import parameterized, parameterized_class

path_versions_1 = [
    ("api/v1/location/", "e19e035"),
    ("api/v1/disarm/", "1_6"),
    ("api/v1/atlas/", "4_7_0"),
    ("api/v1/attack-enterprise/", "16_0"),
    ("api/v1/cwe/", "4_16"),
    ("api/v1/capec/", "3_9"),
]

path_versions_2 = [
    ("api/v1/atlas/", "4_5_2"),
    ("api/v1/attack-enterprise/", "15_1"),
    ("api/v1/cwe/", "4_15"),
    ("api/v1/capec/", "3_8"),
]


@parameterized_class(
    ("path_versions",),
    [
        (path_versions_1,),
        (path_versions_2,),
    ],
)
class TestObjectsDownload(unittest.TestCase):
    path_versions: list[tuple[str, str]]

    def setUp(self):
        self.completed_jobs = set()
        self.jobs = set()
        self.base_url = os.environ['CTIBUTLER_URL']
        for path, version in self.path_versions:
            payload = dict(version=version)
            resp = requests.post(urljoin(self.base_url, path), json=payload)
            print(f"{resp.request.method} {resp.url} [{payload}] => {resp.status_code} [{resp.reason}]")
            resp.raise_for_status()
            job_data = resp.json()
            self.jobs.add(job_data['id'])
        return super().setUp()

    def test_1_job_success(self):
        try_count = 0
        while running_jobs := self.jobs.difference(self.completed_jobs):
            print(running_jobs)
            for job_id in list(running_jobs):
                with self.subTest(f"job {job_id}"):
                    job_data = requests.get(f"{self.base_url}api/v1/jobs/{job_id}/").json()
                    job_status = job_data["state"]
                    if job_status in ["completed", "failed"]:
                        self.completed_jobs.add(job_id)
                        self.assertEqual(job_status, "completed", f"response: {job_data}")
                    else:
                        print(f"job {job_id} status: {job_status}")
            print(f"{len(self.completed_jobs)} of {len(self.jobs)} jobs completed")
            time.sleep(10)
            try_count += 1
            if try_count > 30:
                break

    # def test_2_count_jobs(self):
    #     print(f"{self.jobs=}, {self.completed_jobs=}")
    #     self.assertEqual(self.completed_jobs, self.jobs, "not all jobs has completed/failed")
