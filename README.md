# CTI Butler

[![codecov](https://codecov.io/gh/muchdogesec/ctibutler/graph/badge.svg?token=MGIB1SK13X)](https://codecov.io/gh/muchdogesec/ctibutler)

## Before you begin...

We offer a fully hosted web version of CTI Butler which includes many additional features over those in this codebase. [You can find out more about the web version here](https://www.ctibutler.com/).

## Overview

![](docs/ctibutler.png)

A web API for the following STIX 2.1 datasets:

* MITRE ATT&CK Enterprise
* MITRE ATT&CK ICS
* MITRE ATT&CK Mobile
* MITRE CAPEC
* MITRE CWE
* MITRE ATLAS
* Locations
* DISARM

## tl;dr

[![CTI Butler](https://img.youtube.com/vi/84SgT-ess4E/0.jpg)](https://www.youtube.com/watch?v=84SgT-ess4E)

[Watch the demo](https://www.youtube.com/watch?v=84SgT-ess4E).

## Install

### Download and configure

```shell
# clone the latest code
git clone https://github.com/muchdogesec/ctibutler
```

### Configuration options

CTI Butler has various settings that are defined in an `.env` file.

To create a template for the file:

```shell
cp .env.example .env
```

To see more information about how to set the variables, and what they do, read the `.env.markdown` file.

### Build the Docker Image

```shell
sudo docker compose build
```

### Start the server

```shell
sudo docker compose up
```

### Access the server

The webserver (Django) should now be running on: http://127.0.0.1:8006/

You can access the Swagger UI for the API in a browser at: http://127.0.0.1:8006/api/schema/swagger-ui/

## Quickstart

Once you've got CTI Butler running, you can use the following script to import all current and historical data. See `utilities/README.md`

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).