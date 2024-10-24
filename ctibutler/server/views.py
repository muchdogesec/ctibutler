import re
from django.shortcuts import render
from rest_framework import viewsets, filters, status, decorators

from ctibutler.server.arango_helpers import ATLAS_TYPES, CVE_SORT_FIELDS, LOCATION_TYPES, TLP_TYPES, ArangoDBHelper, ATTACK_TYPES, CWE_TYPES, SOFTWARE_TYPES, CAPEC_TYPES
from ctibutler.server.utils import Pagination, Response, Ordering, split_mitre_version
from ctibutler.worker.tasks import new_task
from . import models
from ctibutler.server import serializers
from django_filters.rest_framework import FilterSet, Filter, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter, BooleanFilter, MultipleChoiceFilter, NumberFilter, NumericRangeFilter, DateTimeFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from textwrap import dedent
# Create your views here.

import textwrap

@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.NVDTaskSerializer,
        summary="Download data for CVEs",
        description=textwrap.dedent(
            """
            Use this data to update the CVE records.\n\n
            The earliest CVE record has a `modified` value of `2007-07-13T04:00:00.000Z`. That said, as a rough guide, we recommend downloading CVEs from `last_modified_earliest` = `2020-01-01` because anything older than this is _generally_ stale.\n\n
            The easiest way to identify the last update time used (to keep CVE records current) is to use the jobs endpoint which will show the `last_modified_earliest` and `last_modified_latest` dates used.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `last_modified_earliest` (required - `YYYY-MM-DD`): earliest modified time for vulnerability
            * `last_modified_latest` (required - `YYYY-MM-DD`): latest modified time for vulnerability \n\n
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        responses={200: serializers.StixObjectsSerializer(many=True)}, filters=True,
        summary="Get Vulnerability Objects for CVEs",
        description=textwrap.dedent(
            """
            Search and filter CVE records. This endpoint only returns the vulnerability objects for matching CVEs.\n\n
            Once you have the CVE ID you want, you can get all associated data linked to it (e.g. Indicator Objects) using the bundle endpoint.\n\n
            If you already know the CVE ID, use the Get a Vulnerability by ID endpoint
            """
        ),
    ),
    retrieve_objects=extend_schema(
        summary='Get a Vulnerability by CVE ID',
        description=textwrap.dedent(
            """
            Return data for a CVE by ID. This endpoint only returns the `vulnerability` object for CVE.\n\n
            If you want all the Objects related to this vulnerability you should use the bundle endpoint for the CVE.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('vulnerabilities', 'vulnerability')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get Relationships for Vulnerability by CVE ID',
        description=textwrap.dedent(
            """
            Return data for a CVE by ID. This endpoint only returns the `vulnerability` object for CVE.\n\n
            If you want all the Objects related to this vulnerability you should use the bundle endpoint for the CVE.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
    bundle=extend_schema(
        summary='Get all objects for a Vulnerability by CVE ID',
        description=textwrap.dedent(
            """
            This endpoint will return all objects related to the Vulnerability. This can include the following:\n\n
            * `vulnerability`: Represents the CVE
            * `indicator`: Contains a pattern identifying products affected by the CVE
            * `relationship` (`indicator`->`vulnerability`)
            * `note`: Represents EPSS scores
            * `sighting`: Represents CISA KEVs
            * `software`: Represents the products listed in the pattern
            * `relationship` (`indicator`->`software`)
            * `weakness` (CWE): represents CWEs linked to the Vulneability (requires `cve-cwe` mode to be run)
            * `relationship` (`vulnerability` (CVE) ->`weakness` (CWE))
            * `attack-pattern` (CAPEC): represents CAPECs in CWEs (linked to Vulnerability) (requires `cve-cwe` and `cwe-capec` mode to be run)
            * `relationship` (`weakness` (CWE) ->`attack-pattern` (CAPEC))
            * `attack-pattern` (ATT&CK Enterprise/ICS/Mobile): represents ATT&CKs in CAPECs in CWEs (linked to Vulnerability) (requires `cve-cwe`, `cwe-capec` and `capec-attack` mode to be run)
            * `relationship` (`attack-pattern` (CAPEC) ->`attack-pattern` (ATT&CK))
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('objects', 'vulnerability')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
    versions=extend_schema(
        responses=serializers.StixVersionsSerializer,
        summary="Get all updates for a Vulnerability by CVE ID",
        description=textwrap.dedent(
            """
            This endpoint will return all the times a Vulnerability has been modified over time as new information becomes available.\n\n
            By default the latest version of objects will be returned by all endpoints. This endpoint is generally most useful to researchers interested in the evolution of what is known about a vulnerability. The version returned can be used to get an older versions of a Vulnerability.
            """
        ),

    ),

)   
class CveView(viewsets.ViewSet):
    openapi_tags = ["CVE"]
    pagination_class = Pagination("vulnerabilities")
    filter_backends = [DjangoFilterBackend]
    serializer_class = serializers.StixObjectsSerializer(many=True)
    lookup_url_kwarg = 'cve_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID, e.g `vulnerability--4d2cad44-0a5a-5890-925c-29d535c3f49e`.'),
        OpenApiParameter('cve_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CVE ID, e.g `CVE-2024-3125`'),

    ]

    
    class filterset_class(FilterSet):
        stix_id = MultipleChoiceFilter(label='Filter the results using the STIX ID of a `vulnerability` object. e.g. `vulnerability--4d2cad44-0a5a-5890-925c-29d535c3f49e`.')
        cve_id = CharFilter(label='Filter the results using a CVE ID. e.g. `CVE-2023-22518`')
        description = CharFilter(label='Filter the results by the description of the Vulnerability. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        has_kev = BooleanFilter(label=dedent('''
        Filter the results to only include those reported by CISA KEV (Known Exploited Vulnerability).
        '''))
        cpes_vulnerable = BaseCSVFilter(label=dedent('''
        Filter Vulnerabilities that are vulnerable to a full or partial CPE Match String. Search is a wildcard to support partial match strings (e.g. `cpe:2.3:o:microsoft:windows` will match `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.\n\n
        `cve-cpe` mode must have been triggered on the Arango CTI Processor endpoint for this to work.
        '''))
        cpes_in_pattern = BaseCSVFilter(label=dedent('''
        Filter Vulnerabilities that contain a full or partial CPE Match String. Note, this will return Vulnerabilities that are vulnerable and not vulnerable (e.g. an operating system might not be vulnerable, but it might be required for software running on it to be vulnerable). Search is a wildcard to support partial match strings (e.g. `cpe:2.3:o:microsoft:windows` will match `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.\n\n
        `cve-cpe` mode must have been triggered on the Arango CTI Processor endpoint for this to work.
        '''))
        weakness_id = BaseCSVFilter(label=dedent("""
            Filter results by weakness (CWE ID). e.g. `CWE-122`.\n\n
            `cve-cwe` mode must have been triggered on the Arango CTI Processor endpoint for this to work.
            """))
        attack_id = BaseCSVFilter(label=dedent(
            """
            Filter results by an ATT&CK technique or sub-technique ID linked to CVE. e.g `T1587`, `T1587.001`.\n\n
            Note, CVEs are not directly linked to ATT&CK techniques. To do this, we follow the path `cve->cwe->capec->attack` to link ATT&CK objects to CVEs. As such, `cve-cwe`, `cwe-capec`, `capec-attack` modes must have been triggered on the Arango CTI Processor endpoint for this to work.
            """))
        cvss_base_score_min = NumberFilter(label="The minumum CVSS score you want. `0` is lowest, `10` is highest.")
        epss_score_min = NumberFilter(label="The minimum EPSS score you want. Between `0` (lowest) and `1` highest to 2 decimal places (e.g. `9.34`).\n\n`cve-epss` mode must have been triggered on the Arango CTI Processor endpoint for this to work.")
        epss_percentile_min = NumberFilter(label="The minimum EPSS percentile you want. Between `0` (lowest) and `1` highest to 2 decimal places (e.g. `9.34`).\n\n`cve-epss` mode must have been triggered on the Arango CTI Processor endpoint for this to work.")
        created_min = DateTimeFilter(label="Is the minumum `created` value (`YYYY-MM-DDThh:mm:ss.sssZ`)")
        created_max = DateTimeFilter(label="Is the maximum `created` value (`YYYY-MM-DDThh:mm:ss.sssZ`)")
        
        modified_min = DateTimeFilter(label="Is the minumum `modified` value (`YYYY-MM-DDThh:mm:ss.sssZ`)")
        modified_max = DateTimeFilter(label="Is the maximum `modified` value (`YYYY-MM-DDThh:mm:ss.sssZ`)")
        sort = ChoiceFilter(choices=[(v, v) for v in CVE_SORT_FIELDS], label="Sort results by")


    def create(self, request, *args, **kwargs):
        serializer = serializers.NVDTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = new_task(serializer.data, models.JobType.CVE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('', request, 'vulnerabilities').get_vulnerabilities()
    
    @decorators.action(methods=['GET'], detail=False, url_path="objects/<str:cve_id>/bundle")
    def bundle(self, request, *args, cve_id=None, **kwargs):
        return ArangoDBHelper('', request).get_cve_bundle(cve_id)
    
    @extend_schema(
            parameters=[
                OpenApiParameter("cve_version", type=OpenApiTypes.DATETIME, description="Return only vulnerability object where `modified` value matches query")
            ]
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cve_id>", detail=False)
    def retrieve_objects(self, request, *args, cve_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_cxe_object(cve_id)
    
    @extend_schema(
            parameters=[
                OpenApiParameter("cve_version", type=OpenApiTypes.DATETIME, description="Return only vulnerability object where `modified` value matches query")
            ]
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cve_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, cve_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_cxe_object(cve_id, relationship_mode=True)
    
    @decorators.action(detail=False, url_path="objects/<str:cve_id>/versions", methods=["GET"], pagination_class=Pagination('versions'))
    def versions(self, request, *args, cve_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_cve_versions(cve_id)
    

@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.NVDTaskSerializer,
        summary="Download CPE data",
        description=textwrap.dedent(
            """
            Use this data to update the CPE records.\n\n
            The earliest CPE was `2007-09-01`. That said, as a rough guide, we recommend downloading CPEs from `last_modified_earliest` = `2015-01-01` because anything older than this is _generally_ stale.\n\n
            Note, Software objects representing CPEs do not have a `modified` time in the way Vulnerability objects do. As such, you will want to store a local index of last_modified_earliest` and `last_modified_latest` used in previous request. Requesting the same dates won't cause an issue (existing records will be skipped) but it will be more inefficient.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `last_modified_earliest` (required - `YYYY-MM-DD`): earliest modified time for CPE
            * `last_modified_latest` (required - `YYYY-MM-DD`): latest modified time for CPE\n\n
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Get Software Objects for CPEs',
        description="Search and filter CPE records.\n\nThis endpoint only returns the `software` objects for matching CPEs.\n\nThis endpoint is useful to find CPEs that can be used to filter CVEs.",
        filters=True,
    ),
    retrieve_objects=extend_schema(
        summary='Get a CPE object by STIX ID',
        description="Retrieve a single STIX `software` object for a CPE using its STIX ID. You can identify a STIX ID using the GET CPEs endpoint.",
        filters=False,
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get Relationships for Object',
        description=textwrap.dedent(
            """
            Return relationships.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
) 
class CpeView(viewsets.ViewSet):
    openapi_tags = ["CPE"]
    pagination_class = Pagination("objects")
    filter_backends = [DjangoFilterBackend]
    serializer_class = serializers.StixObjectsSerializer(many=True)
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The full STIX `id` of the object. e.g. `vulnerability--4d2cad44-0a5a-5890-925c-29d535c3f49e`'),
        OpenApiParameter('cpe_name', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The full CPE name. e.g. `cpe:2.3:a:slicewp:affiliate_program_suite:1.0.13:*:*:*:*:wordpress:*:*`'),
    ]

    
    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results by the STIX ID of the `software` object. e.g. `software--93ff5b30-0322-50e8-90c1-1c3f151c8adc`')
        cpe_match_string = CharFilter(label='Filter CPEs that contain a full or partial CPE Match String. Search is a wildcard to support partial match strings (e.g. `cpe:2.3:o:microsoft:windows` will match `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.')
        vendor = CharFilter(label='Filters CPEs returned by vendor name. Is wildcard search so `goog` will match `google`, `googe`, etc.')
        product = CharFilter(label='Filters CPEs returned by product name. Is wildcard search so `chrom` will match `chrome`, `chromium`, etc.')

        product_type = ChoiceFilter(choices=[('operating-system', 'Operating System'), ('application', 'Application'), ('hardware', 'Hardware')],
                        label='Filters CPEs returned by product type.'
        )
        cve_vulnerable = BaseCSVFilter(label='Filters CPEs returned to those vulnerable to CVE ID specified. e.g. `CVE-2023-22518`.')
        in_cve_pattern = BaseCSVFilter(label='Filters CPEs returned to those referenced CVE ID specified (if you want to only filter by vulnerable CPEs, use the `cve_vulnerable` parameter. e.g. `CVE-2023-22518`.')

    def create(self, request, *args, **kwargs):
        serializer = serializers.NVDTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = new_task(serializer.data, models.JobType.CPE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('', request).get_softwares()

    @decorators.action(methods=['GET'], url_path="objects/<str:cpe_name>", detail=False)
    def retrieve_objects(self, request, *args, cpe_name=None, **kwargs):
        return ArangoDBHelper(f'nvd_cpe_vertex_collection', request).get_cxe_object(cpe_name, type='software', var='cpe')
    
    @decorators.action(methods=['GET'], url_path="objects/<str:cpe_name>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, cpe_name=None, **kwargs):
        return ArangoDBHelper(f'nvd_cpe_vertex_collection', request).get_cxe_object(cpe_name, type='software', var='cpe', relationship_mode=True)
    

    
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Download ATT&CK Objects",
        description=textwrap.dedent(
            """
            Use this data to update ATT&CK records.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `version` (required): the version of ATT&CK you want to download in the format `N_N`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_attack_enterprise.py#L7).\n\n
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Get ATT&CK objects',
        description="Search and filter ATT&CK results.",
        filters=True
    ),
    retrieve_objects=extend_schema(
        summary='Get an ATT&CK object',
        description="Get an ATT&CK object by its STIX ID. To search and filter objects to get an ID use the GET Objects endpoint.",
    ),
    retrieve_object_relationships=extend_schema(
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
)  
class AttackView(viewsets.ViewSet):
    openapi_tags = ["ATT&CK"]
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID'),
        OpenApiParameter('attack_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The ATT&CK ID, e.g `T1659`, `TA0043`, `S0066`'),
    ]

    filter_backends = [DjangoFilterBackend]
    MATRIX_TYPES = ["mobile", "ics", "enterprise"]
    @property
    def matrix(self):
        m: re.Match = re.search(r"/attack-(\w+)/", self.request.path)
        return m.group(1)
    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results using the STIX ID of an object. e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`, `malware--04227b24-7817-4de1-9050-b7b1b57f5866`.')
        attack_id = BaseCSVFilter(label='The ATT&CK IDs of the object wanted. e.g. `T1659`, `TA0043`, `S0066`.')
        description = CharFilter(label='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(label='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in ATTACK_TYPES], label='Filter the results by STIX Object type.')
        attack_version = CharFilter(label="Filter the results by the version of ATT&CK")

    
    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        data['matrix'] = self.matrix
        job = new_task(data, models.JobType.ATTACK_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('', request).get_attack_objects(self.matrix)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('attack_version', description="Filter the results by the version of ATT&CK")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>", detail=False)
    def retrieve_objects(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_object_by_external_id(attack_id)
        
    
    @extend_schema(
            parameters=[
                OpenApiParameter('attack_version', description="Filter the results by the version of ATT&CK")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_object_by_external_id(attack_id, relationship_mode=True)
        
    @extend_schema()
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer)
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_mitre_versions()
    
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_mitre_modified_versions(attack_id)
    

    @classmethod
    def attack_view(cls, matrix_name: str):
        matrix_name_human = matrix_name.title()
        if matrix_name == 'ics':
            matrix_name_human = "ICS"
        @extend_schema_view(
            create=extend_schema(
                responses={201: serializers.JobSerializer
                },
                request=serializers.MitreTaskSerializer,
                summary=f"Download MITRE ATT&CK {matrix_name_human} Objects",
                description=textwrap.dedent(
                    """
                    Use this endpoint to update MITRE ATT&CK records.

                    The following key/values are accepted in the body of the request:

                    * `version` (required): the version of ATT&CK you want to download in the format `N_N`, e.g. `15_1` for `15.1`. You can see all [Enterprise versions here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_attack_enterprise.py#L7), [Mobile versions here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_attack_mobile.py#L7), or [ICS versions here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_attack_ics.py#L7).

                    The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
                    """
                ),
            ),
            list_objects=extend_schema(
                summary=f'Search and filter MITRE ATT&CK {matrix_name_human} objects',
                description=textwrap.dedent(
                    """
                    Search and filter MITRE ATT&CK {matrix_name_human} results.

                    This endpoint with return the entire {matrix_name_human} matrix for reference. However, Vulnerabilities are linked to ATT&CK Techniques and Sub-Techniques only. For reference, these are represented as `attack-pattern` STIX objects.
                    """
                    ),
                filters=True,
            ),
            retrieve_objects=extend_schema(
                summary=f'Get a specific MITRE ATT&CK {matrix_name_human} object by its ID',
                description=textwrap.dedent(
                    """
                    Get an MITRE ATT&CK {matrix_name_human} object by its MITRE ATT&CK ID (e.g. `T1659`, `TA0043`, `S0066`).

                    If you do not know the ID of the object you can use the GET MITRE ATT&CK {matrix_name_human} Objects endpoin to find it.
                    """
                ),
                filters=False,
            ),
            versions=extend_schema(
                summary=f"Get a list of MITRE ATT&CK {matrix_name_human} versions stored in the database",
                description=textwrap.dedent(
                    """
                    It is possible to import multiple versions of ATT&CK using the POST MITRE ATT&CK {matrix_name_human} endpoints. By default, all endpoints will only return the latest version of ATT&CK objects (which generally suits most use-cases).

                    This endpoint allows you to see all imported versions of MITRE ATT&CK {matrix_name_human} available to use, and which version is the default (latest). Typically this endpoint is only interesting for researchers looking to retrieve older ATT&CK versions because you can filter objects by a specific version of ATT&CK on the object endpoints.
                    """
                ),
            ),
            object_versions=extend_schema(
                summary=f"See all version of the MITRE ATT&CK {matrix_name_human} object",
                description=textwrap.dedent(
                    """
                    This endpoint will show the STIX version of the object `modified` and what MITRE ATT&CK versions it appears in.

                    The data returned is useful to see when and object has changed. If you want to see the actual changes, use the diff endpoint.
                    """,
                ),
            ),
            retrieve_object_relationships=extend_schema(
                summary=f'Get the Relationships linked to the MITRE ATT&CK {matrix_name_human} Object',
                description=textwrap.dedent(
                    """
                    This endpoint will return all the STIX `relationship` objects where the ATT&CK object is found as a `source_ref` or a `target_ref`.
                    """
                ),
            ),
        )  
        class TempAttackView(cls):
            matrix = matrix_name
            openapi_tags = [f"ATT&CK {matrix_name_human}"]
        TempAttackView.__name__ = f'{matrix_name.title()}AttackView'
        return TempAttackView
    
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Download CWE objects",
        description=textwrap.dedent(
            """
            Use this data to update CWE records.

            The following key/values are accepted in the body of the request:

            * `version` (required): the version of CWE you want to download in the format `N_N`, e.g. `4_14` for `4.14`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_cwe.py#L7).

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Get CWE objects',
        description=textwrap.dedent(
            """
            Search and filter CWE results. This endpoint will return `weakness` objects. It is most useful for finding CWE IDs that can be used to filter Vulnerability records with on the GET CVE objects endpoints.
            """
        ),
        filters=True,
    ),
    retrieve_objects=extend_schema(
        summary='Get a CWE object',
        description='Get an CWE object by its STIX ID. To search and filter CWE objects to get an ID use the GET Objects endpoint.',
        filters=False,
    ),
    object_versions=extend_schema(
        summary="See available CWE versions for CWE-ID",
        description="See all imported versions available to use.",
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get Relationships for Object',
        description=textwrap.dedent(
            """
            Return relationships.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
)  
class CweView(viewsets.ViewSet):
    openapi_tags = ["CWE"]
    lookup_url_kwarg = 'cwe_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID'),
        OpenApiParameter('cwe_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CWE ID, e.g CWE-73'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results using the STIX ID of an object. e.g. `weakness--f3496f30-5625-5b6d-8297-ddc074fb26c2`.')
        cwe_id = BaseCSVFilter(label='Filter the results by the CWE ID of the object. e.g. `CWE-242`.')
        description = CharFilter(label='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(label='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        # type = ChoiceFilter(choices=[(f,f) for f in CWE_TYPES], label='Filter the results by STIX Object type.')
        cwe_version = CharFilter(label="Filter the results by the version of CWE")

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CWE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_weakness_or_capec_objects()
    
    @extend_schema(
            parameters=[
                OpenApiParameter('cwe_version', description="Filter the results by the version of CWE")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>", detail=False)
    def retrieve_objects(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_object_by_external_id(cwe_id)
        
    
    @extend_schema(
            parameters=[
                OpenApiParameter('cwe_version', description="Filter the results by the version of CWE")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_object_by_external_id(cwe_id, relationship_mode=True)
        
    @extend_schema(summary="See available CWE versions", description="See all imported versions available to use, and which version is the default (latest)")
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer)
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_mitre_versions()
        
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_cwe_vertex_collection', request).get_mitre_modified_versions(cwe_id, source_name='cwe')
       
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Download ATLAS objects",
        description=textwrap.dedent(
            """
            Use this data to update ATLAS records.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `version` (required): the version of ATLAS you want to download in the format `N_N`, e.g. `4_14` for `4.14`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_atlas.py#L7).\n\n
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Get ATLAS objects',
        description='Search and filter ATLAS results. This endpoint will return `weakness` objects. It is most useful for finding ATLAS IDs that can be used to filter Vulnerability records with on the GET CVE objects endpoints.',
        filters=True,
    ),
    retrieve_objects=extend_schema(
        summary='Get a ATLAS object',
        description='Get an ATLAS object by its STIX ID. To search and filter ATLAS objects to get an ID use the GET Objects endpoint.',
        filters=False,
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get Relationships for Object',
        description=textwrap.dedent(
            """
            Return relationships.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
    object_versions=extend_schema(
        summary="See available ATLAS versions for ATLAS-ID",
        description="See all imported versions available to use.",
    ),
)  
class AtlasView(viewsets.ViewSet):
    openapi_tags = ["ATLAS"]
    lookup_url_kwarg = 'atlas_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID'),
        OpenApiParameter('atlas_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The ATLAS ID, e.g `AML.T0000.001`'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results using the STIX ID of an object. e.g. `attack-pattern--64db2878-ae36-46ab-b47a-f71fff575aba`.')
        atlas_id = BaseCSVFilter(label='Filter the results by the ATLAS ID of the object. e.g. `AML.T0000.001`.')
        description = CharFilter(label='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(label='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in ATLAS_TYPES], label='Filter the results by STIX Object type.')
        atlas_version = CharFilter(label="Filter the results by the version of ATLAS")

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.ATLAS_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_weakness_or_capec_objects(types=ATLAS_TYPES, lookup_kwarg=self.lookup_url_kwarg)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('atlas_version', description="Filter the results by the version of ATLAS")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>", detail=False)
    def retrieve_objects(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_object_by_external_id(atlas_id)    
    @extend_schema(
            parameters=[
                OpenApiParameter('atlas_version', description="Filter the results by the version of ATLAS")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_object_by_external_id(atlas_id, relationship_mode=True)
        
    @extend_schema(summary="See available ATLAS versions", description="See all imported versions available to use, and which version is the default (latest)")
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer)
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_mitre_versions()
        
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_atlas_vertex_collection', request).get_mitre_modified_versions(atlas_id, source_name='atlas')
   
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Download CAPEC objects",
        description=textwrap.dedent(
            """
            Use this data to update CAPEC records.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `version` (required): the version of CAPEC you want to download in the format `N_N`, e.g. `3_9` for `3.9`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_capec.py#L7).\n\n
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Get CAPEC objects',
        description="Search and filter CAPEC results.",
        filters=True,
    ),
    retrieve_objects=extend_schema(
        summary='Get a CAPEC object',
        description='Get an CAPEC object by its STIX ID. To search and filter objects to get an ID use the GET Objects endpoint.',
        filters=False,
    ),
    object_versions=extend_schema(
        summary="See available CAPEC versions for CAPEC-ID",
        description="See all imported versions available to use.",
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get Relationships for Object',
        description=textwrap.dedent(
            """
            Return relationships.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
)
class CapecView(viewsets.ViewSet):
    openapi_tags = ["CAPEC"]
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID'),
        OpenApiParameter('capec_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CAPEC ID, e.g CAPEC-699'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results using the STIX ID of an object. e.g. `attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6`, `course-of-action--0002fa37-9334-41e2-971a-cc8cab6c00c4`.')
        capec_id = BaseCSVFilter(label='Filter the results by the CAPEC ID of the object. e.g. `CAPEC-112`.')
        description = CharFilter(label='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(label='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in CAPEC_TYPES], label='Filter the results by STIX Object type.')
        capec_version = CharFilter(label="Filter the results by the version of CAPEC")

    
    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CAPEC_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_weakness_or_capec_objects(types=CAPEC_TYPES, lookup_kwarg=self.lookup_url_kwarg)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('capec_version', description="Filter the results by the version of CAPEC")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>", detail=False)
    def retrieve_objects(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_object_by_external_id(capec_id)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('capec_version', description="Filter the results by the version of CAPEC")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_object_by_external_id(capec_id, relationship_mode=True)
    
    @extend_schema(summary="See available CAPEC versions", description="See all imported versions available to use, and which version is the default (latest)")
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer)
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_mitre_versions()
    
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_capec_vertex_collection', request).get_mitre_modified_versions(capec_id, source_name='capec')
    
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        summary="Trigger arango_cti_processor `mode` to generate relationships.",
        description=textwrap.dedent(
            """
            This endpoint will link together knowledgebases based on the `mode` selected. For more information about how this works see [arango_cti_processor](https://github.com/muchdogesec/arango_cti_processor/), specifically the `--relationship` setting.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `ignore_embedded_relationships` (optional - default: `true`): arango_cti_processor generates SROs to link knowledge-bases. These SROs have embedded relationships inside them. Setting this to `true` (recommended) will generat SROs for these embedded relationships so they can be searched. `false` will ignore them\n\n
            * `modified_min` (optional - default: all time - format: `YYYY-MM-DDTHH:MM:SS.sssZ`): by default arango_cti_processor will run over all objects in the latest version of a framework (e.g. ATT&CK). This is not always effecient, espeically when updating CVE records. As such, you can ask the script to only consider objects with a `modified` time greater than that specified for this field.\n\n
            * `created_min` (optional - default: all time- format: `YYYY-MM-DDTHH:MM:SS.sssZ`): same as `modified_min`, but this time considers `created` time of the object (not `modified` time).
            """
        ),
    ),
)
class ACPView(viewsets.ViewSet):
    openapi_tags = ["Arango CTI Processor"]
    serializer_class = serializers.ACPSerializer
    openapi_path_params = [
            OpenApiParameter(name='mode', enum=list(serializers.ACP_MODES), location=OpenApiParameter.PATH, description='The  [`arango_cti_processor`](https://github.com/muchdogesec/arango_cti_processor/) `--relationship` mode.')
    ]

    def create(self, request, *args, **kwargs):
        serializer = serializers.ACPSerializerWithMode(data={**request.data, **kwargs})
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CTI_PROCESSOR)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

@extend_schema_view(
    list=extend_schema(
        description="Search and filter Jobs. Jobs are triggered for each time a data download request is executed (e.g. GET ATT&CK). The response of these requests will contain a Job ID. Note, Jobs also include Arango CTI Processor runs to join the data together.\n\nNote, for job types `cpe-update` and `cve-update` you might see a lot of urls marked as `errors`. This is expected. This simply means there is no data for the day requested and the script is not smart enough to handle it gracefully.",
        summary="Get Jobs",
        responses={200: serializers.JobSerializer}
    ),
    retrieve=extend_schema(
        description="Get information about a specific Job. To retrieve a Job ID, use the GET Jobs endpoint.\n\nNote, for job types `cpe-update` and `cve-update` you might see a lot of urls marked as `errors`. This is expected. This simply means there is no data for the day requested and the script is not smart enough to handle it gracefully.",
        summary="Get a Job by ID",
    ),
)
class JobView(viewsets.ModelViewSet):
    http_method_names = ["get"]
    serializer_class = serializers.JobSerializer
    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = ["run_datetime", "state", "type", "id"]
    ordering = "run_datetime_descending"
    pagination_class = Pagination("jobs")
    openapi_tags = ["Jobs"]
    lookup_url_kwarg = 'job_id'
    openapi_path_params = [
        OpenApiParameter(lookup_url_kwarg, type=OpenApiTypes.UUID, location=OpenApiParameter.PATH, description='The Job `id`. You can find Jobs and their `id`s using the Get Jobs endpoint.')
    ]

    def get_queryset(self):
        return models.Job.objects.all()
    class filterset_class(FilterSet):
        @staticmethod
        def get_type_choices():
            choices = list(models.JobType.choices)
            for mode, summary in serializers.ACP_MODES.items():
                type = models.JobType.CTI_PROCESSOR
                choices.append((f"{type}--{mode}", summary))

            for mode in AttackView.MATRIX_TYPES:
                type = models.JobType.ATTACK_UPDATE
                choices.append((f"{type}--{mode}", f"The `{mode}` mode of {type}"))
            choices.sort(key=lambda x: x[0])
            return choices
        
        type = ChoiceFilter(
            label='Filter the results by the type of Job',
            choices=get_type_choices(), method='filter_type'
        )
        state = Filter(label='Filter the results by the state of the Job')

        def filter_type(self, qs, field_name, value: str):
            query = {field_name: value}
            if '--' in value:
                type, mode = value.split('--')
                query.update({field_name: type, "parameters__mode":mode})
            return qs.filter(**query)
        
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)



      
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=None,
        summary="Download Location objects",
        description=textwrap.dedent(
            """
            Use this data to update Location records.\n\n\n\n
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Get Location objects',
        description='Search and filter Location results. This endpoint will return `weakness` objects. It is most useful for finding Location IDs that can be used to filter Vulnerability records with on the GET CVE objects endpoints.',
        filters=True,
    ),
    retrieve_objects=extend_schema(
        summary='Get a Location object',
        description='Get an Location object by its STIX ID. To search and filter Location objects to get an ID use the GET Objects endpoint.',
        filters=False,
    ),
    object_versions=extend_schema(
        summary="See available Location versions for Location-ID",
        description="See all imported versions available to use.",
    ),
)  
class LocationView(viewsets.ViewSet):
    openapi_tags = ["Location"]
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")
    arango_collection = "location_vertex_collection"

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results using the STIX ID of an object. e.g. `location--64db2878-ae36-46ab-b47a-f71fff575aba`.')
        name = CharFilter(label='Filter the results by the `name` property of the object. Search is a wildcard, so `Ca` will return all names that contain the string `Tur`, e.g `Turkey`, `Turkmenistan`.')

    def create(self, request, *args, **kwargs):
        job = new_task({}, models.JobType.LOCATION_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_weakness_or_capec_objects(types=LOCATION_TYPES)
    
    @extend_schema(
            parameters=[
                # OpenApiParameter('location_version', description="Filter the results by the version of Location")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:stix_id>", detail=False)
    def retrieve_objects(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object(stix_id)
    
     
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Download TLP objects",
        description=textwrap.dedent(
            """
            Use this data to update TLP records.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `version` (required): the version of TLP you want to download, value is either `1` or `2`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_tlp.py#L7).\n\n
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Get TLP objects',
        description='Search and filter TLP results. This endpoint will return `weakness` objects. It is most useful for finding TLP IDs that can be used to filter Vulnerability records with on the GET CVE objects endpoints.',
        filters=True,
    ),
    retrieve_objects=extend_schema(
        summary='Get a TLP object',
        description='Get an TLP object by its STIX ID. To search and filter TLP objects to get an ID use the GET Objects endpoint.',
        filters=False,
    ),
    object_versions=extend_schema(
        summary="See available TLP versions for TLP-ID",
        description="See all imported versions available to use.",
    ),
)  
class TLPView(viewsets.ViewSet):
    openapi_tags = ["TLP"]
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")
    arango_collection = "tlp_vertex_collection"

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results using the STIX ID of an object. e.g. `marking-definition--64db2878-ae36-46ab-b47a-f71fff575aba`.')
        name = CharFilter(label='Filter the results by the `name` property of the object. e.g `clear`, `amber`.')

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.TLP_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_weakness_or_capec_objects(types=TLP_TYPES)
    
    @extend_schema(
            parameters=[
                # OpenApiParameter('TLP_version', description="Filter the results by the version of TLP")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:stix_id>", detail=False)
    def retrieve_objects(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object(stix_id)
    