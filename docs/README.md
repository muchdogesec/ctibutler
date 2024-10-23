## API

### Endpoints

#### ATT&CK Objects

##### GET ATT&CK

```shell
GET <HOST>/api/v1/attack-<MATRIX_NAME>/
```

Same as Vulmatch.

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### POST ATT&CK

```shell
POST <HOST>/api/v1/attack-<MATRIX_NAME>/
```

Same as Vulmatch.

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET ATT&CK Objects

```shell
GET <HOST>/api/v1/attack-<MATRIX_NAME>/
```

Same as Vulmatch.

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET ATT&CK Object

```shell
GET <HOST>/api/v1/attack-<MATRIX_NAME>/:attack_id
```

Same as Vulmatch.

Possible errors:

* 404 - Not found, or the client does not have access to the resource


##### GET ATT&CK Object version

```shell
GET <HOST>/api/v1/attack-<MATRIX_NAME>/objects/:attack_id/versions/
```

Same as Vulmatch.

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### GET ATT&CK Object relationships

```shell
GET <HOST>/api/v1/attack-<MATRIX_NAME>/objects/:attack_id/relationships/
```

This endpoint returns all SROs where this object is either a `_source` or `_target`

Is paginated.

sort: modified_ascending, modified_descending, created_ascending, created_descending

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

---

#### CWE Objects

##### GET CWEs

```shell
GET <HOST>/api/v1/cwes/
```

Same as Vulmatch.

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### POST CWEs

```shell
POST <HOST>/api/v1/cwes/
```

Same as Vulmatch.

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET CWE Objects

```shell
GET <HOST>/api/v1/cwes/objects/
```

Same as Vulmatch.

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET CWE Object

```shell
GET <HOST>/api/v1/cwes/objects/:cwe_id/
```

Same as Vulmatch.

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### GET CWE Object versions

```shell
GET <HOST>/api/v1/cwes/objects/:cwe_id/versions/
```

Same as Vulmatch.

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### GET CWE Object relationships

```shell
GET <HOST>/api/v1/cwes/objects/:cwe_id/relationships/
```

This endpoint returns all SROs where this object is either a `_source` or `_target`

Is paginated.

sort: modified_ascending, modified_descending, created_ascending, created_descending

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

---

#### ATLAS Objects

##### GET ATLAS

```shell
GET <HOST>/api/v1/atlas/
```

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### POST ATLAS

```shell
POST <HOST>/api/v1/atlas/
```

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET ATLAS Objects

```shell
GET <HOST>/api/v1/atlas/objects/
```

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET ATLAS Object

```shell
GET <HOST>/api/v1/atlas/objects/:atlas_id/
```

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### GET ATLAS Object versions

```shell
GET <HOST>/api/v1/cwes/objects/:atlas_id/versions/
```

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### GET ATLAS Object relationships

```shell
GET <HOST>/api/v1/cwes/objects/:atlas_id/relationships/
```

This endpoint returns all SROs where this object is either a `_source` or `_target`

Is paginated.

sort: modified_ascending, modified_descending, created_ascending, created_descending

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

---

#### CAPEC Objects

##### GET CAPECs

```shell
GET <HOST>/api/v1/capecs/
```

Same as Vulmatch.

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource


##### POST CAPECs

```shell
POST <HOST>/api/v1/capecs/
```

Same as Vulmatch.

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET CAPEC Objects

```shell
GET <HOST>/api/v1/capecs/objects/
```

Same as Vulmatch.

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET CAPEC Object

```shell
GET <HOST>/api/v1/capecs/objects/:capec_id/
```

Same as Vulmatch.

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### GET CAPEC Object version

```shell
GET <HOST>/api/v1/capecs/objects/:capec_id/versions
```

Same as Vulmatch.

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### GET CAPEC Object relationships

```shell
GET <HOST>/api/v1/capec/objects/:capec_id/relationships/
```

This endpoint returns all SROs where this object is either a `_source` or `_target`

Is paginated.

sort: modified_ascending, modified_descending, created_ascending, created_descending

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

---

####  Locations

##### POST Locations

```shell
POST <HOST>/api/v1/locations/
```

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET Location Objects

```shell
GET <HOST>/api/v1/locations/
```

* `type`: `country`, `region`, `sub-region`, `intermediate-region`

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET Location Object

```shell
GET <HOST>/api/v1/locations/objects/:stix_id/
```

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### GET Location Object version

```shell
GET <HOST>/api/v1/locations/objects/:stix_id/versions
```

Possible errors:

* 404 - Not found, or the client does not have access to the resource

##### GET Location Object relationships

```shell
GET <HOST>/api/v1/locations/objects/:stix_id/relationships/
```

This endpoint returns all SROs where this object is either a `_source` or `_target`

Is paginated.

sort: modified_ascending, modified_descending, created_ascending, created_descending

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

---

####  TLPs

##### POST TLPs

```shell
POST <HOST>/api/v1/tlps/
```

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET TLP Objects

```shell
GET <HOST>/api/v1/tlps/
```

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET TLP Object

```shell
GET <HOST>/api/v1/tlps/objects/:stix_id/
```

Possible errors:

* 404 - Not found, or the client does not have access to the resource

---

#### Objects

Same endpoints as Vulmatch.

---

### Jobs

##### Get Jobs

```shell
POST <HOST>/api/v1/jobs
```

Same as Vulmatch.

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### Get Job ID

```shell
POST <HOST>/api/v1/arango_cti_processor/jobs/:job_id
```

Same as Vulmatch.

Possible errors:

* 404 - Not found, or the client does not have access to the resource