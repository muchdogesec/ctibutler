import requests
import time
import json

# Set the base URL and headers
base_url = 'http://127.0.0.1:8005/api/v1'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Versions for attack and CWE updates
attack_versions = ["14_1","15_1"] # add these in order to avoid versioning issues
cwe_versions = ["4_14", "4_15"] # add these in order to avoid versioning issues
capec_versions = ["3_8", "3_9"] # add these in order to avoid versioning issues

# Modes for arango-cti-processor
arango_modes = [
    "capec-attack",
    "cwe-capec"
]

# Function to initiate attack updates with version
def initiate_attack_update(endpoint, version):
    data = {
        "version": version
    }
    print(f"Initiating {endpoint} update with version: {version}")
    response = requests.post(f'{base_url}/{endpoint}/', headers=headers, json=data)
    
    if response.status_code == 201:
        print(f"{endpoint} update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate {endpoint} update: {response.status_code} - {response.text}")
        return None

# Function to initiate the CAPEC update with version
def initiate_capec_update(version):
    data = {
        "version": version
    }
    print(f"Initiating CAPEC update with version: {version}")
    response = requests.post(f'{base_url}/capec/', headers=headers, json=data)
    
    if response.status_code == 201:
        print(f"CAPEC update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate CAPEC update: {response.status_code} - {response.text}")
        return None

# Function to initiate the CWE update with version
def initiate_cwe_update(version):
    data = {
        "version": version
    }
    print(f"Initiating CWE update with version: {version}")
    response = requests.post(f'{base_url}/cwe/', headers=headers, json=data)
    
    if response.status_code == 201:
        print(f"CWE update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate CWE update: {response.status_code} - {response.text}")
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
            else:
                print(f"Job {job_id} still in state: {state}. Waiting for 30 sec before retrying...")
                time.sleep(30)  # Wait for 1 minute before checking again
        else:
            print(f"Failed to check job status: {response.status_code} - {response.text}")
            break

# Function to monitor a single job status and ensure completion before proceeding
def monitor_job_status(job_id, job_name):
    print(f"{job_name} job initiated with ID: {job_id}")
    job_status = check_job_status(job_id)
    
    if job_status and job_status['state'] == 'completed':
        print(f"{job_name} job completed successfully.")
    else:
        print(f"{job_name} job did not complete successfully.")

# Function to initiate arango-cti-processor updates
def initiate_arango_cti_processor_update(mode):
    print(f"Initiating arango-cti-processor update with mode: {mode}")
    response = requests.post(f'{base_url}/arango-cti-processor/{mode}/', headers=headers)
    
    if response.status_code == 201:
        print(f"arango-cti-processor update for {mode} initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate arango-cti-processor update for {mode}: {response.status_code} - {response.text}")
        return None

# Function to monitor and initiate multiple jobs
def monitor_jobs():
    # Step 1: attack-enterprise and attack-ics updates with both versions
    for version in attack_versions:
        job_id = initiate_attack_update("attack-enterprise", version)
        if job_id:
            monitor_job_status(job_id, f"attack-enterprise (version {version})")

        job_id = initiate_attack_update("attack-ics", version)
        if job_id:
            monitor_job_status(job_id, f"attack-ics (version {version})")

    # Step 2: attack-mobile updates with both versions
    for version in attack_versions:
        job_id = initiate_attack_update("attack-mobile", version)
        if job_id:
            monitor_job_status(job_id, f"attack-mobile (version {version})")

    # Step 3: CAPEC update with both versions
    for version in capec_versions:
        job_id = initiate_capec_update(version)
        if job_id:
            monitor_job_status(job_id, f"CAPEC (version {version})")

    # Step 4: CWE update with both versions
    for version in cwe_versions:
        job_id = initiate_cwe_update(version)
        if job_id:
            monitor_job_status(job_id, f"CWE (version {version})")

    # Step 5: Run arango-cti-processor for each mode
    for mode in arango_modes:
        job_id = initiate_arango_cti_processor_update(mode)
        if job_id:
            monitor_job_status(job_id, f"arango-cti-processor ({mode})")

# Run the script
if __name__ == "__main__":
    monitor_jobs()
