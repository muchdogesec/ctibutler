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
	--ignore_embedded_relationships True
```

Note, `ignore_embedded_relationships` is set to `True` above, as it is known to cause problems ingesting all versions of ATT&CK and generating the embedded relationships. Though if you have a capable machine, setting this to `False` should work fine

## OPTIONAL: Download latest versions (at time of writing)

```shell
python3 utilities/import_all_data.py \
	--ignore_embedded_relationships True \
	--attack_enterprise_versions 16_0 \
	--attack_ics_versions 16_0 \
	--attack_mobile_versions 16_0 \
	--cwe_versions 4_16 \
	--capec_versions 3_9 \
	--tlp_versions 2 \
	--atlas_versions 4_5_2 \
	--location_versions ac1bbfc \
	--disarm_versions 1_5
```