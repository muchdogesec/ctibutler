import requests
import time
import json
import sys
import argparse

# Set the base URL and headers
base_url = 'http://127.0.0.1:8006/api/v1'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Default versions for attack and CWE updates
default_attack_enterprise_versions = [
    "1_0", "2_0", "3_0", "4_0", "5_0", "5_1", "5_2", "6_0", "6_1", "6_2", "6_3",
    "7_0", "7_1", "7_2", "8_0", "8_1", "8_2", "9_0", "10_0", "10_1", "11_0", 
    "11_1", "11_2", "11_3", "12_0", "12_1", "13_0", "13_1", "14_0", "14_1", 
    "15_0", "15_1", "16_0"
]
default_attack_ics_versions = [
    "8_0", "8_1", "8_2", "9_0", "10_0", "10_1", "11_0", 
    "11_1", "11_2", "11_3", "12_0", "12_1", "13_0", "13_1", "14_0", "14_1", 
    "15_0", "15_1", "16_0"
]
default_attack_mobile_versions = [
    "1_0", "2_0", "3_0", "4_0", "5_0", "5_1", "5_2", "6_0", "6_1", "6_2", "6_3",
    "7_0", "7_1", "7_2", "8_0", "8_1", "8_2", "9_0", "10_0", "10_1", "11_0-beta", 
    "11_1-beta", "11_2-beta", "11_3", "12_0", "12_1", "13_0", "13_1", "14_0", "14_1", 
    "15_0", "15_1", "16_0"
]
default_cwe_versions = [
    "4_5", "4_6", "4_7", "4_8", "4_9", "4_10", "4_11", "4_12", "4_13",
    "4_14", "4_15", "4_16"
]
default_capec_versions = [
    "3_5", "3_6", "3_7", "3_8", "3_9"
]
default_tlp_versions = [
    "1", "2" 
]
default_atlas_versions = [
    "4_5_2", "4_7_0"
]
default_location_versions = [
    "ac1bbfc"
]
default_disarm_versions = [
    "1_2", "1_3", "1_4", "1_5"
]

# Parse CLI arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Monitor and initiate multiple jobs for updates.")
    
    parser.add_argument('--attack_enterprise_versions', type=str, help="Comma-separated versions for attack-enterprise updates.")
    parser.add_argument('--attack_ics_versions', type=str, help="Comma-separated versions for attack-ics updates.")
    parser.add_argument('--attack_mobile_versions', type=str, help="Comma-separated versions for attack-mobile updates.")
    parser.add_argument('--cwe_versions', type=str, help="Comma-separated versions for CWE updates.")
    parser.add_argument('--capec_versions', type=str, help="Comma-separated versions for CAPEC updates.")
    parser.add_argument('--tlp_versions', type=str, help="Comma-separated versions for TLP updates.")
    parser.add_argument('--atlas_versions', type=str, help="Comma-separated versions for ATLAS updates.")
    parser.add_argument('--location_versions', type=str, help="Comma-separated versions for Location updates.")
    parser.add_argument('--disarm_versions', type=str, help="Comma-separated versions for DISARM updates.")


    # New argument for ignore_embedded_relationships
    parser.add_argument('--ignore_embedded_relationships', type=bool, default=False, help="Set to True to ignore embedded relationships in the update.")
    
    return parser.parse_args()

# Convert comma-separated CLI arguments into a list of versions
def get_versions_from_arg(arg_value, default_versions):
    if arg_value:
        return arg_value.split(',')
    else:
        return default_versions

# Function to initiate attack updates with version
def initiate_update(endpoint, version, ignore_embedded_relationships):
    data = {
        "version": version,
        "ignore_embedded_relationships": ignore_embedded_relationships
    }
    print(f"Initiating {endpoint} update with version: {version}, ignore_embedded_relationships: {ignore_embedded_relationships}")
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
def monitor_jobs(args):
    ignore_embedded_relationships = args.ignore_embedded_relationships  # Use this in each request

    # Step 1: attack-enterprise updates
    attack_enterprise_versions = get_versions_from_arg(args.attack_enterprise_versions, default_attack_enterprise_versions)
    for version in attack_enterprise_versions:
        job_id = initiate_update("attack-enterprise", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"attack-enterprise (version {version})")

    # Step 2: attack-ics updates
    attack_ics_versions = get_versions_from_arg(args.attack_ics_versions, default_attack_ics_versions)
    for version in attack_ics_versions:
        job_id = initiate_update("attack-ics", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"attack-ics (version {version})")

    # Step 3: attack-mobile updates
    attack_mobile_versions = get_versions_from_arg(args.attack_mobile_versions, default_attack_mobile_versions)
    for version in attack_mobile_versions:
        job_id = initiate_update("attack-mobile", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"attack-mobile (version {version})")

    # Step 4: CAPEC updates
    capec_versions = get_versions_from_arg(args.capec_versions, default_capec_versions)
    for version in capec_versions:
        job_id = initiate_update("capec", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"CAPEC (version {version})")

    # Step 5: CWE updates
    cwe_versions = get_versions_from_arg(args.cwe_versions, default_cwe_versions)
    for version in cwe_versions:
        job_id = initiate_update("cwe", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"CWE (version {version})")

    # Step 6: TLP updates
    tlp_versions = get_versions_from_arg(args.tlp_versions, default_tlp_versions)
    for version in tlp_versions:
        job_id = initiate_update("tlp", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"TLP (version {version})")

    # Step 7: Location updates
    location_versions = get_versions_from_arg(args.location_versions, default_location_versions)
    for version in location_versions:
        job_id = initiate_update("location", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"Location (version {version})")

    # Step 8: ATLAS updates
    atlas_versions = get_versions_from_arg(args.atlas_versions, default_atlas_versions)
    for version in atlas_versions:
        job_id = initiate_update("atlas", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"ATLAS (version {version})")

    # Step 9: DISARM updates
    disarm_versions = get_versions_from_arg(args.disarm_versions, default_disarm_versions)
    for version in disarm_versions:
        job_id = initiate_update("disarm", version, ignore_embedded_relationships)
        if job_id:
            monitor_job_status(job_id, f"DISARM (version {version})")

# Run the script
if __name__ == "__main__":
    args = parse_arguments()
    monitor_jobs(args)
