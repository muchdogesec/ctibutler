import logging
from pathlib import Path
import shutil
from urllib.parse import urljoin

import requests
from ctibutler.server.models import Job
from ctibutler.server import models
from celery import Task
import tempfile
from datetime import datetime, date, timedelta
import typing
from django.conf import settings
from .celery import app
from stix2arango.stix2arango import Stix2Arango

from arango_cti_processor.managers import TechniqueTactic
from arango_cti_processor.__main__ import run_all as run_task_with_acp
import logging

if typing.TYPE_CHECKING:
    from ..import settings


def create_celery_task_from_job(job: Job):
    data = job.parameters
    match job.type:
        case models.JobType.LOCATION_UPDATE:
            task = run_mitre_task(data, job, 'location')
        case models.JobType.ATLAS_UPDATE:
            task = run_mitre_task(data, job, 'atlas')
        case models.JobType.ATTACK_UPDATE:
            task = run_mitre_task(data, job, f'attack-{data["matrix"]}')
        case models.JobType.CWE_UPDATE:
            task = run_mitre_task(data, job, 'cwe')
        case models.JobType.CAPEC_UPDATE:
            task = run_mitre_task(data, job, 'capec')
        case models.JobType.CTI_PROCESSOR:
            task = run_acp_task(data, job)
        case models.JobType.DISARM_UPDATE:
            task = run_mitre_task(data, job, 'disarm')
    task.set_immutable(True)
    return task



def new_task(data, type, job=None) -> Job:
    job = Job.objects.create(type=type, parameters=data)
    create_celery_task_from_job(job).apply_async()
    return job

def run_acp_task(data: dict, job: Job):
    options = data.copy()
    options['database'] = settings.ARANGODB_DATABASE
    options['modes'] = [data['mode']]

    task =  acp_task.s(options, job_id=job.id)
    return (task | remove_temp_and_set_completed.si(None, job_id=job.id))
    

def run_mitre_task(data, job: Job, mitre_type='cve'):
    version = data['version'].replace('.', '_')
    match mitre_type:
        case 'attack-enterprise':
            url = urljoin(settings.ATTACK_ENTERPRISE_BUCKET_ROOT_PATH, f"enterprise-attack-{version}.json")
            collection_name = 'mitre_attack_enterprise'
        case 'attack-mobile':  # pragma: no cover
            url = urljoin(settings.ATTACK_MOBILE_BUCKET_ROOT_PATH, f"mobile-attack-{version}.json")
            collection_name = 'mitre_attack_mobile'
        case 'attack-ics':
            url = urljoin(settings.ATTACK_ICS_BUCKET_ROOT_PATH, f"ics-attack-{version}.json")
            collection_name = 'mitre_attack_ics'
        case "cwe":
            url = urljoin(settings.CWE_BUCKET_ROOT_PATH, f"cwe-bundle-v{version}.json")
            collection_name = 'mitre_cwe'
        case "capec":
            url = urljoin(settings.CAPEC_BUCKET_ROOT_PATH, f"stix-capec-v{version}.json")
            collection_name = 'mitre_capec'
        case "atlas":
            url = urljoin(settings.ATLAS_BUCKET_ROOT_PATH, f"mitre-atlas-v{version}.json")
            collection_name = 'mitre_atlas'
        case "location":
            url = urljoin(settings.LOCATION_BUCKET_ROOT_PATH, f"location-bundle-v{version}.json")
            collection_name = "location"
        case "disarm":
            url = urljoin(settings.DISARM_BUCKET_ROOT_PATH, f"disarm-bundle-v{version}.json")
            collection_name = "disarm"
        case _:
            raise NotImplementedError("Unknown type for mitre task")
    
    temp_dir = get_job_temp_dir(job)
    task = download_file.si(url, temp_dir, job_id=job.id) | upload_file.s(collection_name, version=version, job_id=job.id, params=job.parameters)
    return (task | remove_temp_and_set_completed.si(temp_dir, job_id=job.id))

def get_job_temp_dir(job):
    return str(Path(tempfile.gettempdir())/f"ctibutler/{job.type}--{str(job.id)}")

class CustomTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        job = Job.objects.get(pk=kwargs['job_id'])
        job.state = models.JobState.FAILED
        job.errors.append(f"celery task {self.name} failed with: {exc}")
        job.save()
        try:
            logging.info('removing directory')
            path = get_job_temp_dir(job)
            shutil.rmtree(path)
            logging.info(f'directory `{path}` removed')
        except Exception as e:
            logging.error(f'delete dir failed: {e}')
        return super().on_failure(exc, task_id, args, kwargs, einfo)
    
    def before_start(self, task_id, args, kwargs):
        if not kwargs.get('job_id'):
            raise Exception("rejected: `job_id` not in kwargs")
        return super().before_start(task_id, args, kwargs)
    

@app.task(base=CustomTask)
def download_file(urlpath, tempdir, job_id=None):
    Path(tempdir).mkdir(parents=True, exist_ok=True)
    logging.info('downloading bundle at `%s`', urlpath)
    job = Job.objects.get(pk=job_id)
    if job.state == models.JobState.PENDING:
        job.state = models.JobState.PROCESSING
        job.save()
    resp = requests.get(urlpath)
    resp.raise_for_status()
    filename = Path(tempdir)/resp.url.split('/')[-1]
    filename.write_bytes(resp.content)
    return str(filename)


@app.task(base=CustomTask)
def upload_file(filename, collection_name, version=None, job_id=None, params=dict()):
    stix2arango_note=f'version={version}'

    logging.info('uploading %s with note: %s', filename, stix2arango_note)
    s2a = Stix2Arango(
        file=str(filename),
        database=settings.ARANGODB_DATABASE,
        collection=collection_name,
        stix2arango_note=stix2arango_note,
        host_url=settings.ARANGODB_HOST_URL,
        username=settings.ARANGODB_USERNAME,
        password=settings.ARANGODB_PASSWORD,
        is_large_file=True,
        create_db=False,
        create_collection=False,
        **params,
    )
    s2a.run()
    TechniqueTactic.make_relations(collection_name, version, database=settings.ARANGODB_DATABASE, stix2arango_note=stix2arango_note)


@app.task(base=CustomTask)
def acp_task(options, job_id=None):
    job = Job.objects.get(pk=job_id)
    run_task_with_acp(**options)

@app.task(base=CustomTask)
def remove_temp_and_set_completed(path: str, job_id: str=None):
    if path:
        logging.info('removing directory: %s', path)
        shutil.rmtree(path, ignore_errors=True)
    job = Job.objects.get(pk=job_id)
    job.state = models.JobState.COMPLETED
    job.save()


from celery import signals
@signals.worker_ready.connect
def mark_old_jobs_as_failed(**kwargs):
    Job.objects.filter(state=models.JobState.PENDING).update(state = models.JobState.FAILED, errors=["marked as failed on startup"])
