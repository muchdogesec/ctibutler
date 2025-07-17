from urllib.parse import urljoin
import requests
import time
import json
import sys
import argparse

# Set the base URL and headers
base_url = 'http://127.0.0.1:8006/api/v1'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    #'Authorization': 'Token XXX'
}

def retrieve_available_versions(path):
    url = urljoin(base_url+'/', f'{path}/versions/available/')
    resp = requests.get(url)
    assert resp.status_code == 200
    versions = resp.json()
    return versions

# Default versions for attack and CWE updates
default_attack_enterprise_versions = retrieve_available_versions('attack-enterprise')
default_attack_ics_versions = retrieve_available_versions('attack-ics')
default_attack_mobile_versions = retrieve_available_versions('attack-mobile')
default_cwe_versions = retrieve_available_versions('cwe')
default_capec_versions = retrieve_available_versions('capec')
default_atlas_versions = retrieve_available_versions('atlas')
default_location_versions = retrieve_available_versions('location')
default_disarm_versions = retrieve_available_versions('disarm')

def parse_versions(all_versions: list):
    def parse(versions):
        versions = [v.replace('_', '.') for v in versions.split(',')]
        if 'all' in versions:
            return all_versions
        unavailable_versions = set()
        for v in versions:
            if v not in all_versions:
                unavailable_versions.add(v)
        if unavailable_versions:
            raise argparse.ArgumentTypeError(f"unavailable versions: {', '.join(unavailable_versions)}")
        return sorted(versions, key=all_versions.index)
    return parse
            

# Parse CLI arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Monitor and initiate multiple jobs for updates.")
    
    parser.add_argument('--attack_enterprise_versions', default=[], type=parse_versions(default_attack_enterprise_versions), help="Comma-separated versions for attack-enterprise updates.")
    parser.add_argument('--attack_ics_versions', default=[], type=parse_versions(default_attack_ics_versions), help="Comma-separated versions for attack-ics updates.")
    parser.add_argument('--attack_mobile_versions', default=[], type=parse_versions(default_attack_mobile_versions), help="Comma-separated versions for attack-mobile updates.")
    parser.add_argument('--cwe_versions', default=[], type=parse_versions(default_cwe_versions), help="Comma-separated versions for CWE updates.")
    parser.add_argument('--capec_versions', default=[], type=parse_versions(default_capec_versions), help="Comma-separated versions for CAPEC updates.")
    parser.add_argument('--atlas_versions', default=[], type=parse_versions(default_atlas_versions), help="Comma-separated versions for ATLAS updates.")
    parser.add_argument('--location_versions', default=[], type=parse_versions(default_location_versions), help="Comma-separated versions for Location updates.")
    parser.add_argument('--disarm_versions', default=[], type=parse_versions(default_disarm_versions), help="Comma-separated versions for DISARM updates.")



    # New argument for ignore_embedded_relationships
    parser.add_argument('--ignore_embedded_relationships', type=bool, default=False, help="Set to True to ignore embedded relationships in the update.")
    
    args = parser.parse_args()
    print("parsed args:", args)
    return args

# Function to initiate attack updates with version
def initiate_update(endpoint, version, ignore_embedded_relationships):
    data = {
        "version": version,
        "ignore_embedded_relationships": False,
        "ignore_embedded_relationships_sro": True,
        "ignore_embedded_relationships_smo": True
    }
    print(f"Initiating {endpoint} update with version: {version}")
    response = requests.post(f'{base_url}/{endpoint}/', headers=headers, json=data)
    
    if response.status_code == 201:
        print(f"{endpoint} update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate {endpoint} update: {response.status_code} - {response.text}")
        return None

# Function to check the job status and wait for it to complete
def check_job_status(job_id):
    job_url = f'{base_url}/jobs/{job_id}/'
    while True:
        print(f"Checking job status for job ID: {job_id}")
        response = requests.get(job_url, headers=headers)
        if response.status_code == 200:
            job_status = response.json()
            print(f"Job status response: {json.dumps(job_status, indent=2)}")
            state = job_status['state']
            
            if state == 'completed':
                print(f"Job {job_id} completed successfully.")
                return job_status
            elif state in ['failed', 'processing_failed', 'retrieve_failed']:
                print(f"Job {job_id} failed with state: {state}. Exiting with critical error.")
                sys.exit(1)  # Exit with an error status code
            else:
                print(f"Job {job_id} still in state: {state}. Waiting for 5 sec before retrying...")
                time.sleep(5)  # Wait for 5 seconds before checking again
        else:
            print(f"Failed to check job status: {response.status_code} - {response.text}")
            break

# Function to initiate and monitor the CAPEC follow-up query
def initiate_capec_followup():
    data = {
        "ignore_embedded_relationships": True
    }
    print(f"Initiating CAPEC follow-up query...")
    response = requests.post(f'{base_url}/arango-cti-processor/capec-attack/', headers=headers, json=data)
    
    if response.status_code == 201:
        print("CAPEC follow-up query initiated successfully.")
        job_id = response.json()['id']
        return job_id
    else:
        print(f"Failed to initiate CAPEC follow-up query: {response.status_code} - {response.text}")
        return None

# Function to initiate and monitor the CWE follow-up query
def initiate_cwe_followup():
    data = {
        "ignore_embedded_relationships": True
    }
    print(f"Initiating CWE follow-up query...")
    response = requests.post(f'{base_url}/arango-cti-processor/cwe-capec/', headers=headers, json=data)
    
    if response.status_code == 201:
        print("CWE follow-up query initiated successfully.")
        job_id = response.json()['id']
        return job_id
    else:
        print(f"Failed to initiate CWE follow-up query: {response.status_code} - {response.text}")
        return None

# Function to monitor the job status and ensure completion
def monitor_job_status(job_id, job_name):
    print(f"{job_name} job initiated with ID: {job_id}")
    job_status = check_job_status(job_id)
    
    if job_status and job_status['state'] == 'completed':
        print(f"{job_name} job completed successfully.")
    else:
        print(f"{job_name} job did not complete successfully.")

# Function to monitor and initiate multiple jobs
def monitor_jobs(args):
    ignore_embedded_relationships = args.ignore_embedded_relationships  # Use this in each request

    # Step 1: attack-enterprise updates
    for version in args.attack_enterprise_versions:
        job_id = initiate_update("attack-enterprise", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"attack-enterprise (version {version})")

    # Step 2: attack-ics updates
    for version in args.attack_ics_versions:
        job_id = initiate_update("attack-ics", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"attack-ics (version {version})")

    # Step 3: attack-mobile updates
    for version in args.attack_mobile_versions:
        job_id = initiate_update("attack-mobile", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"attack-mobile (version {version})")

    # Step 4: CAPEC updates
    for version in args.capec_versions:
        job_id = initiate_update("capec", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"CAPEC (version {version})")
            
            # Run the follow-up CAPEC query
            followup_job_id = initiate_capec_followup()
            if followup_job_id:
                monitor_job_status(followup_job_id, f"CAPEC follow-up query (version {version})")

    # Step 5: CWE updates
    for version in args.cwe_versions:
        job_id = initiate_update("cwe", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"CWE (version {version})")
            
            # Run the follow-up CWE query
            followup_job_id = initiate_cwe_followup()
            if followup_job_id:
                monitor_job_status(followup_job_id, f"CWE follow-up query (version {version})")

    # Step 7: Location updates
    for version in args.location_versions:
        job_id = initiate_update("location", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"Location (version {version})")

    # Step 8: ATLAS updates
    for version in args.atlas_versions:
        job_id = initiate_update("atlas", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"ATLAS (version {version})")

    # Step 9: DISARM updates
    for version in args.disarm_versions:
        job_id = initiate_update("disarm", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"DISARM (version {version})")

# Run the script
if __name__ == "__main__":
    args = parse_arguments()
    monitor_jobs(args)