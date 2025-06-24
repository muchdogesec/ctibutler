import pytest
from ctibutler.worker.populate_dbs import setup_arangodb

def pytest_sessionstart():
    setup_arangodb()

@pytest.fixture
def eager_celery():
    from ctibutler.worker.celery import app
    app.conf.task_always_eager = True
    app.conf.broker_url = 'redis://goog.ls:1235/0/1/'
    yield
    app.conf.task_always_eager = False

# @pytest.fixture(scope="package", autouse=True)
# def django_db_setup(django_db_setup, django_db_blocker):
#     with django_db_blocker.unblock():
#         yield