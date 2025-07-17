## Setup env

```shell
python3 -m venv ctibutler-venv
source ctibutler-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
````

The scripts below will use the API to import data...

## RECOMMENDED: Download all data

```shell
python3 utilities/import_all_data.py \
	--ignore_embedded_relationships True \
	--attack_enterprise_versions all \
	--attack_ics_versions all \
	--attack_mobile_versions all \
	--cwe_versions all \
	--capec_versions all \
	--atlas_versions all \
	--location_versions all \
	--disarm_versions all
```

The script is hardcoded to ignore the generation of embedded refs from SRO and SMO objects (`--ignore_embedded_relationships_smo True` `--ignore_embedded_relationships_sro True`) which are not useful -- generally SDO / SCO embedded refs are useful (`--ignore_embedded_relationships_smo False` is set in script)

## OPTIONAL: Download latest versions (at time of writing)

```shell
python3 utilities/import_all_data.py \
	--ignore_embedded_relationships True \
	--attack_enterprise_versions 16_0,17_0 \
	--attack_ics_versions 16_0,17_0 \
	--attack_mobile_versions 16_0,17_0 \
	--cwe_versions 4_16,4_17 \
	--capec_versions 3_8,3_9 \
	--atlas_versions 4_9_0 \
	--location_versions 1_0 \
	--disarm_versions 1_5,1_6
```

To see available versions (these are the files that CTI Butler versions/available endpoints use to report versions, then replace `.` with `_`), 

* `attack_enterprise_versions`: https://downloads.ctibutler.com/mitre-attack-enterprise-repo-data/version.txt
* `attack_ics_versions`: https://downloads.ctibutler.com/mitre-attack-ics-repo-data/version.txt
* `attack_mobile_versions`: https://downloads.ctibutler.com/mitre-attack-mobile-repo-data/version.txt
* `cwe_versions`: https://downloads.ctibutler.com/cwe2stix-manual-output/version.txt
* `capec_versions`: https://downloads.ctibutler.com/mitre-capec-repo-data/version.txt
* `atlas_versions`: https://downloads.ctibutler.com/mitre-atlas-repo-data/version.txt
* `location_versions`: https://downloads.ctibutler.com/location2stix-manual-output/version.txt
* `disarm_versions`: https://downloads.ctibutler.com/disarm2stix-manual-output/version.txt