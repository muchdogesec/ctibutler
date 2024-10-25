## Setup env

```shell
pip3 install requests
```

## Download all data

```shell
python3 utilities/import_all_data.py
```

## Download latest versions (at time of writing)

```shell
python3 utilities/import_all_data.py \
	--attack_enterprise_versions 15_1 \
	--attack_ics_versions 15_1 \
	--attack_mobile_versions 15_1 \
	--cwe_versions 4_15 \
	--capec_versions 3_9 \
	--tlp_versions 2 \
	--atlas_versions 4_5_2 \
	--location_versions ac1bbfc
```