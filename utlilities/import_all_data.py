import requests
import time
import json
import sys

# Set the base URL and headers
base_url = 'http://127.0.0.1:8006/api/v1'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Versions for attack and CWE updates
# add in ascending version order to avoid versioning issues
attack_enterprise_versions = [
    "1_0", "2_0", "3_0", "4_0", "5_0", "5_1", "5_2", "6_0", "6_1", "6_2", "6_3",
    "7_0", "7_1", "7_2", "8_0", "8_1", "8_2", "9_0", "10_0", "10_1", "11_0", 
    "11_1", "11_2", "11_3", "12_0", "12_1", "13_0", "13_1", "14_0", "14_1", 
    "15_0", "15_1"
]
attack_ics_versions = [
    "8_0", "8_1", "8_2", "9_0", "10_0", "10_1", "11_0", 
    "11_1", "11_2", "11_3", "12_0", "12_1", "13_0", "13_1", "14_0", "14_1", 
    "15_0", "15_1"
]
attack_mobile_versions = [
    "1_0", "2_0", "3_0", "4_0", "5_0", "5_1", "5_2", "6_0", "6_1", "6_2", "6_3",
    "7_0", "7_1", "7_2", "8_0", "8_1", "8_2", "9_0", "10_0", "10_1", "11_0-beta", 
    "11_1-beta", "11_2-beta", "11_3", "12_0", "12_1", "13_0", "13_1", "14_0", "14_1", 
    "15_0", "15_1"
]
cwe_versions = [
    "4_5", "4_6", "4_7", "4_8", "4_9", "4_10", "4_11", "4_12", "4_13",
    "4_14", "4_15",
]
capec_versions = [
    "3_5", "3_6", "3_7", "3_8", "3_9"
]
tlp_versions = [
    "1", "2" 
]
atlas_versions = [
    "4_5_2"
]
location_versions = [
    "ac1bbfc"
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

# Function to initiate a location update without a version
def initiate_location_update():
    print("Initiating location update without a version")
    response = requests.post(f'{base_url}/location/', headers=headers)
    
    if response.status_code == 201:
        print("Location update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate location update: {response.status_code} - {response.text}")
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
                print(f"Job {job_id} still in state: {state}. Waiting for 30 sec before retrying...")
                time.sleep(30)  # Wait for 30 seconds before checking again
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

# Function to monitor and initiate multiple jobs
def monitor_jobs():
    # Step 1: attack-enterprise updates
    for version in attack_enterprise_versions:
        job_id = initiate_attack_update("attack-enterprise", version)
        if job_id:
            monitor_job_status(job_id, f"attack-enterprise (version {version})")

    # Step 2: attack-ics updates
    for version in attack_ics_versions:
        job_id = initiate_attack_update("attack-ics", version)
        if job_id:
            monitor_job_status(job_id, f"attack-ics (version {version})")

    # Step 3: attack-mobile update
    for version in attack_mobile_versions:
        job_id = initiate_attack_update("attack-mobile", version)
        if job_id:
            monitor_job_status(job_id, f"attack-mobile (version {version})")

    # Step 4: CAPEC update
    for version in capec_versions:
        job_id = initiate_capec_update(version)
        if job_id:
            monitor_job_status(job_id, f"CAPEC (version {version})")

    # Step 5: CWE update
    for version in cwe_versions:
        job_id = initiate_cwe_update(version)
        if job_id:
            monitor_job_status(job_id, f"CWE (version {version})")

    # Step 6 TLP update
    for version in tlp_versions:
        job_id = initiate_tlp_update(version)
        if job_id:
            monitor_job_status(job_id, f"TLP (version {version})")

    # Step 7: Location update
    for version in location_versions:
        job_id = initiate_location_update(version)
        if job_id:
            monitor_job_status(job_id, f"Location (version {version})")

    # Step 8: ATLAS update
    for version in atlas_versions:
        job_id = initiate_atlas_update(version)
        if job_id:
            monitor_job_status(job_id, f"ATLAS (version {version})")

# Run the script
if __name__ == "__main__":
    monitor_jobs()