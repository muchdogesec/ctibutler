from unittest.mock import patch
import schemathesis
import pytest
from ctibutler.wsgi import application as wsgi_app
from hypothesis import settings
from hypothesis import strategies
from schemathesis.specs.openapi.checks import negative_data_rejection, positive_data_acceptance

from tests.utils import Transport

attack_ids = [
    "G0096",
    "M1016",
    "attack-pattern--7d356151-a69d-404e-896b-71618952702a",
    "campaign--b4e5a4a9-f3be-4631-ba8f-da6ebb067fac",
    "course-of-action--feff9142-e8c2-46f4-842b-bd6fb3d41157",
]
capec_ids = [
    "CAPEC-699",
    "CAPEC-701",
    "attack-pattern--c9b31907-c466-4325-af55-c418aea8b964",
    "attack-pattern--2618d0a4-06d0-4bde-8271-2df61ed8297a"
]

schema = schemathesis.openapi.from_wsgi("/api/schema/?format=json", wsgi_app)
schema.config.base_url = "http://localhost:8006/"

@pytest.fixture(autouse=True)
def override_transport(monkeypatch, client):
    ## patch transport.get
    from schemathesis import transport
    monkeypatch.setattr(transport, "get", lambda _: Transport())

@pytest.mark.django_db(transaction=True)
@schema.given(
    object_id=strategies.sampled_from([x for x in attack_ids+capec_ids if len(x) > 12]),
    capec_id=strategies.sampled_from(capec_ids),
    attack_id=strategies.sampled_from(attack_ids),
)
@schema.exclude(method="POST").parametrize()
@settings(max_examples=30)
def test_api(case: schemathesis.Case, **kwargs):
    for k, v in kwargs.items():
        if k in case.path_parameters:
            case.path_parameters[k] = v
    case.call_and_validate(excluded_checks=[negative_data_rejection, positive_data_acceptance])


@pytest.mark.django_db(transaction=True)
@schema.include(method="POST").parametrize()
@patch('ctibutler.worker.tasks.create_celery_task_from_job')
def test_imports(mock, case: schemathesis.Case):
    case.call_and_validate(excluded_checks=[negative_data_rejection, positive_data_acceptance])
