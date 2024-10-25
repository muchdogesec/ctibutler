## Setup env

```shell
pip3 install requests
```

## Download all data

```shell
python3 utilities/import_all_data.py
```

If you have access to the server, you can also run [stix2arango utility scripts](https://github.com/muchdogesec/stix2arango/tree/main/utilities) directly, as follows;

```shell
python3 utilities/arango_cti_processor/insert_archive_attack_enterprise.py \
	--database ctibutler && \
python3 utilities/arango_cti_processor/insert_archive_attack_ics.py \
	--database ctibutler && \
python3 utilities/arango_cti_processor/insert_archive_attack_mobile.py \
	--database ctibutler && \
python3 utilities/arango_cti_processor/insert_archive_capec.py \
	--database ctibutler && \
python3 utilities/arango_cti_processor/insert_archive_cwe.py \
	--database ctibutler && \
python3 utilities/arango_cti_processor/insert_archive_location.py \
	--database ctibutler && \
python3 utilities/arango_cti_processor/insert_archive_tlp.py \
	--database ctibutler && \
python3 utilities/arango_cti_processor/insert_archive_disarm.py \
	--database ctibutler
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