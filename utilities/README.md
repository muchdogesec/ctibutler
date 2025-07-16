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
python3 utilities/import_all_data.py
```

The script is hardcoded to ignore the generation of embedded refs from SRO and SMO objects (`--ignore_embedded_relationships_smo True` `--ignore_embedded_relationships_sro True`) which are not useful -- generally SDO / SCO embedded refs are useful (`--ignore_embedded_relationships_smo False` is set in script)

## OPTIONAL: Download latest versions (at time of writing)

```shell
python3 utilities/import_all_data.py \
	--ignore_embedded_relationships True \
	--attack_enterprise_versions 17_0 \
	--attack_ics_versions 17_0 \
	--attack_mobile_versions 17_0 \
	--cwe_versions 4_17 \
	--capec_versions 3_9 \
	--atlas_versions 4_9_0 \
	--location_versions e19e035 \
	--disarm_versions 1_6
```