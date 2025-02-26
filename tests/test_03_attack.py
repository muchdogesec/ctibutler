import os
import time
import unittest
from urllib.parse import urljoin

import requests

class TestAttack(unittest.TestCase):
    LATEST_VERSION = "16.0"
    VERSIONS = ["16.0", "15.1"]
    def setUp(self):
        self.base_url = os.environ['CTIBUTLER_URL']
        return super().setUp()
    
    def test_1_versions(self):
        url = urljoin(self.base_url, "api/v1/attack-enterprise/versions/")
        data = requests.get(url).json()
        self.assertEqual(data['latest'], self.LATEST_VERSION, f"expected latest version to be v{self.LATEST_VERSION}")
        self.assertEqual(data['versions'], self.VERSIONS, f"expected {self.VERSIONS}")
    
    def test_2_count_objects(self):
        LATEST_COUNT = 1765
        V15_1_COUNT = 1695
        url = urljoin(self.base_url, "api/v1/attack-enterprise/objects/")        # send no version
        data_no_version = requests.get(url)
        self.assertEqual(data_no_version.json()["total_results_count"], LATEST_COUNT, f"expected no version (v16_0) to have {LATEST_COUNT} items")
        # send version == v16.0
        data_with_version = requests.get(url, params=dict(attack_version="16_0"))
        self.assertEqual(data_no_version.json()["total_results_count"], data_with_version.json()["total_results_count"], "expected no version and v16.0 to have the same count")
        # send version == v15.1
        data_with_old_version = requests.get(url, params=dict(attack_version="15_1"))
        self.assertEqual(data_with_old_version.json()["total_results_count"], V15_1_COUNT, f"expected v15_1 to have {V15_1_COUNT} items")

        
