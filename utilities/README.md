## Setup env

```shell
pip3 install requests
```

## Download all data

```shell
python3 utilities/import_all_data.py \
	--ignore_embedded_relationships True
```

Note, `ignore_embedded_relationships` is set to `true` above, as it is known to cause problems ingesting all versions of ATT&CK and generating the embedded relationships. Though if you have a capable machine, setting this to `False` should work fine

## Download latest versions (at time of writing)

```shell
python3 utilities/import_all_data.py \
	--ignore_embedded_relationships False \
	--attack_enterprise_versions 15_1 \
	--attack_ics_versions 15_1 \
	--attack_mobile_versions 15_1 \
	--cwe_versions 4_15 \
	--capec_versions 3_9 \
	--tlp_versions 2 \
	--atlas_versions 4_5_2 \
	--location_versions ac1bbfc
```