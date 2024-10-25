import os
from celery import Celery
# Set the default Django settings module for the 'celery' program.

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ctibutler.settings')

app = Celery('ctibutler')


app.config_from_object('os:environ', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()
