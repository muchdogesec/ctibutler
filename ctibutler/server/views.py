import re
from django.shortcuts import render
from rest_framework import viewsets, filters, status, decorators

from ctibutler.server.arango_helpers import ATLAS_TYPES, CVE_SORT_FIELDS, DISARM_TYPES, LOCATION_TYPES, ArangoDBHelper, ATTACK_TYPES, CWE_TYPES, SOFTWARE_TYPES, CAPEC_TYPES, LOCATION_SUBTYPES
from ctibutler.server.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR
from ctibutler.server.utils import Pagination, Response, Ordering, split_mitre_version
from ctibutler.worker.tasks import new_task
from . import models
from ctibutler.server import serializers
from django_filters.rest_framework import FilterSet, Filter, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter, BooleanFilter, MultipleChoiceFilter, NumberFilter, NumericRangeFilter, DateTimeFilter, BaseInFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes
from textwrap import dedent
# Create your views here.

import textwrap

REVOKED_AND_DEPRECATED_PARAMS = [
    OpenApiParameter('include_revoked', type=OpenApiTypes.BOOL, description="By default all objects with `revoked` are ignored. Set this to `true` to include them."),
    OpenApiParameter('include_deprecated', type=OpenApiTypes.BOOL, description="By default all objects with `x_mitre_deprecated` are ignored. Set this to `true` to include them."),
]
BUNDLE_PARAMS =  ArangoDBHelper.get_schema_operation_parameters()+ [
            OpenApiParameter(
                "include_embedded_refs",
                description=textwrap.dedent(
                    """
                    If `ignore_embedded_relationships` is set to `false` in the POST request to download data, stix2arango will create SROS for embedded relationships (e.g. from `created_by_refs`). You can choose to show them (`true`) or hide them (`false`) using this parameter. Default value if not passed is `true`.
                    """
                ),
                type=OpenApiTypes.BOOL
            )
]

@extend_schema_view(
    create=extend_schema(
    ),
    list_objects=extend_schema(
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
        filters=True
    ),
    retrieve_objects=extend_schema(
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
        parameters=REVOKED_AND_DEPRECATED_PARAMS,
    ),
    retrieve_object_relationships=extend_schema(
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship'), 400: DEFAULT_400_ERROR},
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters() + REVOKED_AND_DEPRECATED_PARAMS,
    ),

    bundle=extend_schema(
        responses={200: ArangoDBHelper.get_paginated_response_schema(), 400: DEFAULT_400_ERROR},
        parameters=BUNDLE_PARAMS,
    ),
)  
class AttackView(viewsets.ViewSet):
    openapi_tags = ["ATT&CK"]
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`, `malware--04227b24-7817-4de1-9050-b7b1b57f5866`)'),
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
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`, `malware--04227b24-7817-4de1-9050-b7b1b57f5866`.')
        attack_id = BaseCSVFilter(help_text='The ATT&CK IDs of the object wanted. e.g. `T1659`, `TA0043`, `S0066`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in ATTACK_TYPES], help_text='Filter the results by STIX Object type.')
        attack_version = CharFilter(help_text="By default only the latest ATT&CK version objects will be returned. You can enter a specific ATT&CK version here. e.g. `13.1`. You can get a full list of versions on the GET ATT&CK versions endpoint.")
        include_revoked = BooleanFilter(help_text="By default all objects with `revoked` are ignored. Set this to `true` to include them.")
        include_deprecated = BooleanFilter(help_text="By default all objects with `x_mitre_deprecated` are ignored. Set this to `true` to include them.")
        alias = CharFilter(help_text='Filter the results by the `x_mitre_aliases` property of the object. Search is a wildcard, so `sun` will return all objects with x_mitre_aliases that contains the string `sun`, e.g `SUNBURST`.')

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
                OpenApiParameter('attack_version', description="By default only the latest ATT&CK version objects will be returned. You can enter a specific ATT&CK version here. e.g. `13.1`. You can get a full list of versions on the GET ATT&CK versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>", detail=False)
    def retrieve_objects(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_object_by_external_id(attack_id, revokable=True)

    @extend_schema(
            parameters=[
                OpenApiParameter('attack_version', description="By default only the latest ATT&CK version objects will be returned. You can enter a specific ATT&CK version here. e.g. `13.1`. You can get a full list of versions on the GET ATT&CK versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_object_by_external_id(attack_id, relationship_mode=True, revokable=True)

    @extend_schema(
            parameters=[
                OpenApiParameter('attack_version', description="By default only the latest ATT&CK version objects will be returned. You can enter a specific ATT&CK version here. e.g. `13.1`. You can get a full list of versions on the GET ATT&CK versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>/bundle", detail=False)
    def bundle(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_object_by_external_id(attack_id, revokable=True, bundle=True)

    @extend_schema()
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer)
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_mitre_versions()

    @extend_schema(filters=False, parameters=REVOKED_AND_DEPRECATED_PARAMS)
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
                responses={
                    201: OpenApiResponse(
                        serializers.JobSerializer,
                        examples=[
                            OpenApiExample(
                                "",
                                value={
                                    "id": "fbc43f28-6929-4b55-9559-326191701e48",
                                    "type": "attack-update",
                                    "state": "pending",
                                    "errors": [],
                                    "run_datetime": "2024-10-25T14:21:02.850924Z",
                                    "completion_time": "2024-10-25T14:22:09.966635Z",
                                    "parameters": {
                                        "matrix": matrix_name,
                                        "version": "1_0",
                                        "ignore_embedded_relationships": True,
                                    },
                                },
                            )
                        ],
                    ),
                    400: DEFAULT_400_ERROR
                },
                request=serializers.MitreTaskSerializer,
                summary=f"Download MITRE ATT&CK {matrix_name_human} Objects",
                description=textwrap.dedent(
                    """
                    Use this endpoint to update MITRE ATT&CK records. [More information about MITRE ATT&CK here](https://attack.mitre.org/).

                    The following key/values are accepted in the body of the request:

                    * `version` (required): the version of ATT&CK you want to download in the format `N_N`, e.g. `16_0` for `16.0`. You can see all [Enterprise versions here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_attack_enterprise.py#L7), [Mobile versions here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_attack_mobile.py#L7), or [ICS versions here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_attack_ics.py#L7).
                    * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

                    The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).

                    Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
                    """
                ),
            ),
            list_objects=extend_schema(
                summary=f"Search and filter MITRE ATT&CK {matrix_name_human} objects",
                description=textwrap.dedent(
                    """
                    Search and filter MITRE ATT&CK objects.

                    MITRE ATT&CK objects map to STIX objects as follows

                    * Collection: `x-mitre-collection`
                    * Matrix: `x-mitre-matrix`
                    * Tactic: `x-mitre-tactic`
                    * Techniques: `attack-pattern`
                    * Sub-techniques: `attack-pattern` where `x_mitre_is_subtechnique = true` (Enterprise, Mobile only)
                    * Mitigation: `course-of-action`
                    * Groups: `intrusion-set`
                    * Software (malicious): `malware`
                    * Software (benign): `tool` (Enterprise, Mobile only)
                    * Campaign: `campaign`
                    * Data Source: `x-mitre-data-source`
                    * Data Component: `x-mitre-data-component`
                    * Asset: `x-mitre-asset` (ICS only)
                    * Identity: `identity` (for MITRE and DOGESEC)
                    * Marking definitions: `marking-definitions` for TLPs (v1) and copyright statements
                    """
                ),
                filters=True,
            ),
            retrieve_objects=extend_schema(
                summary=f"Get a specific MITRE ATT&CK {matrix_name_human} object by its ID",
                description=textwrap.dedent(
                    """
                    Get a MITRE ATT&CK object by its MITRE ATT&CK ID (e.g. `T1659`, `TA0043`, `S0066`).

                    If you do not know the ID of the object you can use the GET MITRE ATT&CK Objects endpoint to find it.
                    """
                ),
                filters=False,
            ),
            versions=extend_schema(
                summary=f"Get a list of MITRE ATT&CK {matrix_name_human} versions stored in the database",
                description=textwrap.dedent(
                    """
                    It is possible to import multiple versions of ATT&CK using the POST MITRE ATT&CK endpoint. By default, all endpoints will only return the latest version of ATT&CK objects (which generally suits most use-cases).

                    This endpoint allows you to see all imported versions of MITRE ATT&CK available to use, and which version is the latest (the default version for the objects returned).

                    Note, to search in the database you can use the `_stix2arango_note` property and the value `version=N_N" e.g. `version=16_0` for `16.0`.
                    """
                ),
            ),
            object_versions=extend_schema(
                summary=f"See all versions of the MITRE ATT&CK {matrix_name_human} object",
                description=textwrap.dedent(
                    """
                    This endpoint will show the STIX versions of the object (`modified` property) and what MITRE ATT&CK versions it appears in.

                    The data returned is useful to see when and object has changed.
                    """,
                ),
            ),
            retrieve_object_relationships=extend_schema(
                summary=f"Get the Relationships linked to the MITRE ATT&CK {matrix_name_human} Object",
                description=textwrap.dedent(
                    """
                    This endpoint will return all the STIX `relationship` objects where the ATT&CK object is found as a `source_ref` or a `target_ref`.

                    If you want to see an overview of how MITRE ATT&CK objects are linked, [see this diagram](https://miro.com/app/board/uXjVKBgHZ2I=/).

                    MITRE ATT&CK objects can also be `target_ref` from CAPECs objects. Requires POST arango-cti-processor request using `capec-attack` mode for this data to show.
                    """
                ),
            ),
            bundle=extend_schema(
                summary=f"Generate a bundle linked to the MITRE ATT&CK {matrix_name_human} Object",
                description=textwrap.dedent(
                    """
                    This endpoint will return all the STIX `relationship` objects where the ATT&CK object is found as a `source_ref`.

                    If you want to see an overview of how MITRE ATT&CK objects are linked, [see this diagram](https://miro.com/app/board/uXjVKBgHZ2I=/).
                    """
                ),
            )
        )
        class TempAttackView(cls):
            matrix = matrix_name
            openapi_tags = [f"ATT&CK {matrix_name_human}"]
        TempAttackView.__name__ = f'{matrix_name.title()}AttackView'
        return TempAttackView

@extend_schema_view(
    create=extend_schema(
        responses={
                    201: OpenApiResponse(
                        serializers.JobSerializer,
                        examples=[
                            OpenApiExample(
                                "",
                                value={
                                    "id": "85e78220-6387-4be1-81ea-b8373c89aa92",
                                    "type": "cwe-update",
                                    "state": "pending",
                                    "errors": [],
                                    "run_datetime": "2024-10-25T10:39:25.925090Z",
                                    "completion_time": "2024-10-25T10:39:41.551515Z",
                                    "parameters": {
                                        "version": "4_15"
                                    }
                                },
                            )
                        ],
                    ), 400: DEFAULT_400_ERROR
                },
        request=serializers.MitreTaskSerializer,
        summary="Download MITRE CWE objects",
        description=textwrap.dedent(
            """
            Use this data to update CWE records. [More information about MITRE CWE here](https://cwe.mitre.org/).

            The following key/values are accepted in the body of the request:

            * `version` (required): the version of CWE you want to download in the format `N_N`, e.g. `4_16` for `4.16`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_cwe.py#L7).
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Search and filter MITRE CWE objects',
        description=textwrap.dedent(
            """
            Search and filter MITRE CWE objects.

            The following STIX object types can be returned in this response:

            * `weakness`: represent the CWE object
            * `grouping`: groups the CWE object by external groupings, [as shown here](https://cwe.mitre.org/data/index.html).
            * `identity`: the cwe2stix identity
            * `marking-definitions`: for cwe2stix and TLPs (v2)
            """
        ),
        filters=True,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_objects=extend_schema(
        summary='Get a CWE object',
        description=textwrap.dedent(
            """
            Get an CWE object by its ID (e.g. `CWE-242` `CWE-250`).

            If you do not know the ID of the object you can use the GET MITRE CWE Objects endpoint to find it.
            """
        ),
        filters=False,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    object_versions=extend_schema(
        summary="See all versions of the CWE object",
        description=textwrap.dedent(
            """
            This endpoint will show the STIX versions of the object (`modified` property) and what CWE versions it appears in.

            The data returned is useful to see when and object has changed.
            """
        ),
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get the Relationships linked to MITRE CWE Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the CWE object is found as a `source_ref` or a `target_ref`.

            If you want to see an overview of how MITRE CWE objects are linked, [see this diagram](https://miro.com/app/board/uXjVKpOg6bM=/).

            MITRE CWE objects can also be `source_ref` to CAPEC objects. Requires POST arango-cti-processor request using `cwe-capec` mode for this data to show.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship'), 400: DEFAULT_400_ERROR},
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters(),
    ),
    bundle=extend_schema(
        summary='Generate a Bundle linked to MITRE CWE Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the CWE object is found as a `source_ref`.

            If you want to see an overview of how MITRE CWE objects are linked, [see this diagram](https://miro.com/app/board/uXjVKpOg6bM=/).

            MITRE CWE objects can also be `source_ref` to CAPEC objects. Requires POST arango-cti-processor request using `cwe-capec` mode for this data to show.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema(), 400: DEFAULT_400_ERROR},
        parameters=BUNDLE_PARAMS,
    ),
)  
class CweView(viewsets.ViewSet):
    openapi_tags = ["CWE"]
    lookup_url_kwarg = 'cwe_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `weakness--f3496f30-5625-5b6d-8297-ddc074fb26c2`, `grouping--000ee024-ad9c-5557-8d49-2573a8e788d2`)'),
        OpenApiParameter('cwe_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CWE ID, e.g `CWE-242`, `CWE-250`'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `weakness--f3496f30-5625-5b6d-8297-ddc074fb26c2`, `grouping--000ee024-ad9c-5557-8d49-2573a8e788d2`.')
        cwe_id = BaseCSVFilter(help_text='Filter the results by the CWE ID of the object. e.g. `CWE-242` `CWE-250`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        # type = ChoiceFilter(choices=[(f,f) for f in CWE_TYPES], help_text='Filter the results by STIX Object type.')
        cwe_version = CharFilter(help_text="By default only the latest CWE version objects will be returned. You can enter a specific CWE version here. e.g. `4.13`. You can get a full list of versions on the GET CWE versions endpoint.")

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
                OpenApiParameter('cwe_version', description="By default only the latest CWE version objects will be returned. You can enter a specific CWE version here. e.g. `4.13`. You can get a full list of versions on the GET CWE versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>", detail=False)
    def retrieve_objects(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_object_by_external_id(cwe_id)
        
    
    @extend_schema(
            parameters=[
                OpenApiParameter('cwe_version', description="By default only the latest CWE version objects will be returned. You can enter a specific CWE version here. e.g. `4.13`. You can get a full list of versions on the GET CWE versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_object_by_external_id(cwe_id, relationship_mode=True)        
    
    @extend_schema(
            parameters=[
                OpenApiParameter('cwe_version', description="By default only the latest CWE version objects will be returned. You can enter a specific CWE version here. e.g. `4.13`. You can get a full list of versions on the GET CWE versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>/bundle", detail=False)
    def bundle(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_object_by_external_id(cwe_id, bundle=True)
        
    @extend_schema(
        summary="See available CWE versions",
        description=textwrap.dedent(
            """
            It is possible to import multiple versions of CWE using the POST MITRE CWE endpoint. By default, all endpoints will only return the latest version of CWE objects (which generally suits most use-cases).

            This endpoint allows you to see all imported versions of MITRE CWE available to use, and which version is the latest (the default version for the objects returned).

            Note, to search in the database you can use the `_stix2arango_note` property and the value `version=N_N" e.g. `version=4_16` for `4.16`.
            """
            ),
        )
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer)
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_mitre_versions()
        
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_cwe_vertex_collection', request).get_mitre_modified_versions(cwe_id, source_name='cwe')

@extend_schema_view(
    create=extend_schema(
        responses={
                    201: OpenApiResponse(
                        serializers.JobSerializer,
                        examples=[
                            OpenApiExample(
                                "",
                                value={
                                    "id": "d18c2179-3b05-4d24-bd34-d4935ad30e23",
                                    "type": "capec-update",
                                    "state": "pending",
                                    "errors": [],
                                    "run_datetime": "2024-10-25T10:38:25.850756Z",
                                    "completion_time": "2024-10-25T10:38:39.369972Z",
                                    "parameters": {
                                        "version": "3_9"
                                    }
                                },
                            )
                        ],
                    ), 400: DEFAULT_400_ERROR
                },
        request=serializers.MitreTaskSerializer,
        summary="Download MITRE CAPEC objects",
        description=textwrap.dedent(
            """
            Use this data to update MITRE CAPEC records. [More information about MITRE CAPEC here](https://capec.mitre.org/).

            The following key/values are accepted in the body of the request:

            * `version` (required): the version of CAPEC you want to download in the format `N_N`, e.g. `3_9` for `3.9`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_capec.py#L7).
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Search and filter MITRE CAPEC objects',
        description=textwrap.dedent(
            """
            Search and filter MITRE CAPEC objects.

            The following STIX object types can be returned in this response:

            * `attack-pattern`: represent CAPECs
            * `course-of-action`: represents ways to respond to CAPECs
            * `identity`: for MITRE and DOGESEC
            * `marking-definitions`: for TLPs (v1) and copyright statements            
            """
        ),
        filters=True,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_objects=extend_schema(
        summary='Get a CAPEC object',
        description=textwrap.dedent(
            """
            Get a CAPEC object by its ID (e.g. `CAPEC-112`, `CAPEC-699`).

            If you do not know the ID of the object you can use the GET MITRE CAPEC Objects endpoint to find it.
            """
        ),
        filters=False,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    object_versions=extend_schema(
        summary="See all versions of the MITRE CAPEC object",
        description=textwrap.dedent(
            """
            This endpoint will show the STIX versions of the object (`modified` property) and what CAPEC versions it appears in.

            The data returned is useful to see when and object has changed.
            """
        ),
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get the Relationships linked to MITRE CAPEC Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the CAPEC object is found as a `source_ref` or a `target_ref`.

            MITRE CAPEC objects can also be `source_ref` from ATT&CK Enterprise objects. Requires POST arango-cti-processor request using `capec-attack` mode for this data to show.

            MITRE CAPEC objects can also be `target_ref` to CWE objects. Requires POST arango-cti-processor request using `cwe-capec` mode for this data to show.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship'), 400: DEFAULT_400_ERROR},
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters(),
    ),
    bundle=extend_schema(
        summary='Generate a Bundle linked to MITRE CAPEC Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the CAPEC object is found as a `source_ref`.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema(), 400: DEFAULT_400_ERROR},
        parameters=BUNDLE_PARAMS,
    ),
)
class CapecView(viewsets.ViewSet):
    openapi_tags = ["CAPEC"]
    lookup_url_kwarg = 'capec_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6`, `course-of-action--0002fa37-9334-41e2-971a-cc8cab6c00c4`)'),
        OpenApiParameter('capec_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CAPEC ID, e.g `CAPEC-112`, `CAPEC-699`'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6`, `course-of-action--0002fa37-9334-41e2-971a-cc8cab6c00c4`.')
        capec_id = BaseCSVFilter(help_text='Filter the results by the CAPEC ID of the object. e.g. `CAPEC-112`, `CAPEC-699`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in CAPEC_TYPES], help_text='Filter the results by STIX Object type.')
        capec_version = CharFilter(help_text="By default only the latest CAPEC version objects will be returned. You can enter a specific CAPEC version here. e.g. `3.7`. You can get a full list of versions on the GET CAPEC versions endpoint.")

    
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
                OpenApiParameter('capec_version', description="By default only the latest CAPEC version objects will be returned. You can enter a specific CAPEC version here. e.g. `3.7`. You can get a full list of versions on the GET CAPEC versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>", detail=False)
    def retrieve_objects(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_object_by_external_id(capec_id)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('capec_version', description="By default only the latest CAPEC version objects will be returned. You can enter a specific CAPEC version here. e.g. `3.7`. You can get a full list of versions on the GET CAPEC versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_object_by_external_id(capec_id, relationship_mode=True)
        
    @extend_schema(
            parameters=[
                OpenApiParameter('capec_version', description="By default only the latest CAPEC version objects will be returned. You can enter a specific CAPEC version here. e.g. `3.7`. You can get a full list of versions on the GET CAPEC versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>/bundle", detail=False)
    def bundle(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_object_by_external_id(capec_id, bundle=True)
    
    @extend_schema(
        summary="Get a list of CAPEC versions stored in the database",
        description=textwrap.dedent(
            """
            It is possible to import multiple versions of CAPEC using the POST MITRE CAPEC endpoint. By default, all endpoints will only return the latest version of CAPEC objects (which generally suits most use-cases).

            This endpoint allows you to see all imported versions of MITRE CAPEC available to use, and which version is the latest (the default version for the objects returned).

            Note, to search in the database you can use the `_stix2arango_note` property and the value `version=N_N" e.g. `version=3_9` for `3.9`.
            """
            ),
        )
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer)
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_mitre_versions()
    
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_capec_vertex_collection', request).get_mitre_modified_versions(capec_id, source_name='capec')

@extend_schema_view(
    create=extend_schema(
        responses={
                    201: OpenApiResponse(
                        serializers.JobSerializer,
                        examples=[
                            OpenApiExample(
                                "",
                                value={
                                    "id": "972730a4-3f99-47d5-ba6a-5bce0c749081",
                                    "type": "arango-cti-processor",
                                    "state": "pending",
                                    "errors": [],
                                    "run_datetime": "2024-10-22T12:37:56.999198Z",
                                    "completion_time": "2024-10-22T12:38:09.323409Z",
                                    "parameters": {
                                        "mode": "cwe-capec",
                                        "ignore_embedded_relationships": True
                                    }
                                },
                            )
                        ],
                    ), 400: DEFAULT_400_ERROR
                },
        summary="Trigger arango_cti_processor `mode` to generate relationships.",
        description=textwrap.dedent(
            """
            This endpoint will link together knowledgebases based on the `mode` selected. For more information about how this works see [arango_cti_processor](https://github.com/muchdogesec/arango_cti_processor/), specifically the `--relationship` setting.\

            The following key/values are accepted in the body of the request:

            * `ignore_embedded_relationships` (optional - default: `false`): arango_cti_processor generates SROs to link knowledge-bases. These SROs have embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them
            * `modified_min` (optional - default: all time - format: `YYYY-MM-DDTHH:MM:SS.sssZ`): by default arango_cti_processor will run over all objects in the latest version of a framework (e.g. ATT&CK). This is not always efficient. As such, you can ask the script to only consider objects with a `modified` time greater than that specified for this field. Generally it's recommended you don't pass this option, unless you know what you're doing.
            * `created_min` (optional - default: all time- format: `YYYY-MM-DDTHH:MM:SS.sssZ`): same as `modified_min`, but this time considers `created` time of the object (not `modified` time). Again it's recommended you don't pass this option, unless you know what you're doing.
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
        description=textwrap.dedent(
            """
            Search and filter Jobs. Jobs are triggered for each time a data download request is executed (e.g. POST ATT&CK) or requests to join data (e.g. POST Arango CTI Processor). 
            """
        ),
        summary="Get Jobs",
        responses={200: serializers.JobSerializer, 400: DEFAULT_400_ERROR}
    ),
    retrieve=extend_schema(
        description=textwrap.dedent(
            """
            Get information about a specific Job. To retrieve a Job ID, use the GET Jobs endpoint.
            """
        ),
        summary="Get a Job by ID",
        responses={200: serializers.JobSerializer, 400: DEFAULT_404_ERROR},
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
            help_text='Filter the results by the type of Job',
            choices=get_type_choices(), method='filter_type'
        )
        state = Filter(help_text='Filter the results by the state of the Job')

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
        responses={
                    201: OpenApiResponse(
                        serializers.JobSerializer,
                        examples=[
                            OpenApiExample(
                                "",
                                value={
                                     "id": "eb050fc4-c075-4c1b-9d6c-09f498f24dda",
                                    "type": "atlas-update",
                                    "state": "pending",
                                    "errors": [],
                                    "run_datetime": "2024-10-22T13:02:38.795046Z",
                                    "completion_time": "2024-10-22T13:02:39.904610Z",
                                    "parameters": {
                                        "version": "4_5_2"
                                    }
                                },
                            )
                        ],
                    ), 400: DEFAULT_400_ERROR
                },
        request=serializers.MitreTaskSerializer,
        summary="Download MITRE ATLAS objects",
        description=textwrap.dedent(
            """
            Use this data to update ATLAS records. [More information about MITRE ATLAS here](https://atlas.mitre.org/).

            The following key/values are accepted in the body of the request:

            * `version` (required): the version of ATLAS you want to download in the format `N_N_N`, e.g. `4_7_0` for `4.7.0`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_atlas.py#L7).
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Search and filter MITRE ATLAS objects',
        description=textwrap.dedent(
            """
            Search and filter MITRE ATLAS objects.
            """
        ),
        filters=True,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_objects=extend_schema(
        summary='Get an ATLAS object',
        description=textwrap.dedent(
            """
            Get an ATLAS object by its ID (e.g. `AML.TA0002`, `AML.T0000`).

            If you do not know the ID of the object you can use the GET MITRE ATLAS Objects endpoint to find it.
            """
        ),
        filters=False,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get the Relationships linked to the MITRE ATLAS Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the ATLAS object is found as a `source_ref` or a `target_ref`.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship'), 400: DEFAULT_400_ERROR},
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters(),
    ),
    bundle=extend_schema(
        summary='Generate a Bundle linked to the MITRE ATLAS Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the ATLAS object is found as a `source_ref`.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema(), 400: DEFAULT_400_ERROR},
        parameters=BUNDLE_PARAMS,
    ),
    object_versions=extend_schema(
        summary="See all versions of the ATLAS object",
        description=textwrap.dedent(
            """
            This endpoint will show the STIX versions of the object (`modified` property) and what ATLAS versions it appears in.

            The data returned is useful to see when and object has changed.
            """
        ),
    ),
)  
class AtlasView(viewsets.ViewSet):
    openapi_tags = ["ATLAS"]
    lookup_url_kwarg = 'atlas_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `attack-pattern--64db2878-ae36-46ab-b47a-f71fff575aba`, `x-mitre-tactic--6b232c1e-ada7-4cd4-b538-7a1ef6193e2f`)'),
        OpenApiParameter('atlas_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The ATLAS ID, e.g `AML.TA0002`, `AML.T0000`'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `attack-pattern--64db2878-ae36-46ab-b47a-f71fff575aba`, `x-mitre-tactic--6b232c1e-ada7-4cd4-b538-7a1ef6193e2f`.')
        atlas_id = BaseCSVFilter(help_text='Filter the results by the ATLAS ID of the object. e.g. `AML.T0000.001`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in ATLAS_TYPES], help_text='Filter the results by STIX Object type.')
        atlas_version = CharFilter(help_text="By default only the latest ATLAS version objects will be returned. You can enter a specific ATLAS version here. e.g. `4.5.2`. You can get a full list of versions on the GET ATLAS versions endpoint.")

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
        
    @extend_schema(
            parameters=[
                OpenApiParameter('atlas_version', description="Filter the results by the version of ATLAS")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>/bundle", detail=False)
    def bundle(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_object_by_external_id(atlas_id, bundle=True)
        
    @extend_schema(
        summary="See available ATLAS versions",
        description=textwrap.dedent(
            """
            It is possible to import multiple versions of ATLAS using the POST MITRE ATLAS endpoint. By default, all endpoints will only return the latest version of ATLAS objects (which generally suits most use-cases).

            This endpoint allows you to see all imported versions of MITRE ATLAS available to use, and which version is the latest (the default version for the objects returned).

            Note, to search in the database you can use the `_stix2arango_note` property and the value `version=N_N_N" e.g. `version=4_7_0` for `4.7.0`.
            """
            ),
        )
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer)
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_mitre_versions()
        
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_atlas_vertex_collection', request).get_mitre_modified_versions(atlas_id, source_name='atlas')


@extend_schema_view(
    create=extend_schema(
        responses={
                    201: OpenApiResponse(
                        serializers.JobSerializer,
                        examples=[
                            OpenApiExample(
                                "",
                                value={
                                     "id": "e6dab411-162b-4797-82b1-8355a9d51138",
                                    "type": "location-update",
                                    "state": "pending",
                                    "errors": [],
                                    "run_datetime": "2024-10-24T15:04:38.328698Z",
                                    "completion_time": "2024-10-24T15:04:47.655397Z",
                                    "parameters": {
                                        "version": "ac1bbfc"
                                    }
                                },
                            )
                        ],
                    ), 400: DEFAULT_400_ERROR
                },
        request=serializers.MitreTaskSerializer,
        summary="Download Location objects",
        description=textwrap.dedent(
            """
            Use this data to update Location records.

            The following key/values are accepted in the body of the request:

            * `version` (required): the versions of Locations bundle you want to download in the format `XXXXXXX`, e.g. `59da722`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_locations.py#L9C6-L9C13).
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Get Location objects',
        description=textwrap.dedent(
            """
            Search and filter Location objects. Four types of Locations are supported;

            * Countries (e.g. `France`)
            * Intermediate regions (e.g. `Channel Islands`)
            * Sub-regions (e.g. `Western Europe`)
            * Regions (e.g. `Europe`)
            """
        ),
        filters=True,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_objects=extend_schema(
        summary='Get a Location object',
        description=textwrap.dedent(
            """
            Get a Location object by its STIX ID (e.g. `location--bc9ab5f5-cb71-5f3f-a4aa-5265053b8e68`, `location--10f646f3-2693-5a48-b544-b13b7afaa327`)
            
            If you do not know the ID of the object you can use the GET MITRE ATLAS Objects endpoint to find it.
            """
        ),
        filters=False,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    object_versions=extend_schema(
        summary="See all versions of the Location object",
        description=textwrap.dedent(
            """
            This endpoint will show the STIX versions of the object (`modified` property) and what Location versions it appears in.

            The data returned is useful to see when and object has changed.
            """
        ),
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get the Relationships linked to the Location object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the Location object is found as a `source_ref` or a `target_ref`.

            If you want to see an overview of how Location objects are linked, [see this diagram](https://miro.com/app/board/uXjVKAj06DQ=/).
            """
        ),
        filters=False,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters(),
    )
)  
class LocationView(viewsets.ViewSet):
    openapi_tags = ["Location"]
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID of the object (e.g. `location--bc9ab5f5-cb71-5f3f-a4aa-5265053b8e68`, `location--10f646f3-2693-5a48-b544-b13b7afaa327`)'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")
    arango_collection = "location_vertex_collection"

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `location--bc9ab5f5-cb71-5f3f-a4aa-5265053b8e68`, `location--10f646f3-2693-5a48-b544-b13b7afaa327`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `Ca` will return all names that contain the string `Tur`, e.g `Turkey`, `Turkmenistan`.')
        alpha3_code = CharFilter(help_text="Filter by alpha-3 code of the country (e.g `MEX`, `USA`). Only works with country type locations.")
        alpha2_code = CharFilter(help_text="Filter by alpha-2 code of the country (e.g `MX`, `DE`). Only works with country type locations.")
        location_type = BaseInFilter(choices=[(t, t) for t in LOCATION_SUBTYPES], help_text="Filter by location type")

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.LOCATION_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        more_filters = []
        helper = ArangoDBHelper(self.arango_collection, request)
        more_binds = dict()
        if helper.query_as_array('alpha3_code'):
            more_filters.append("FILTER doc.external_references[? ANY FILTER CURRENT IN @alpha3_matchers]")
            more_binds['alpha3_matchers'] = [dict(source_name='alpha-3', external_id=code) for code in helper.query_as_array('alpha3_code')]
        if helper.query_as_array('alpha2_code'):
            more_filters.append("FILTER doc.country IN @alpha2_matchers")
            more_binds['alpha2_matchers'] = helper.query_as_array('alpha2_code')
        if helper.query_as_array('location_type'):
            more_filters.append("FILTER doc.external_references[? ANY FILTER CURRENT IN @location_type_matchers]")
            more_binds['location_type_matchers'] = [dict(source_name='type', external_id=code) for code in helper.query_as_array('location_type')]
        return helper.get_weakness_or_capec_objects(types=LOCATION_TYPES, more_binds=more_binds, more_filters=more_filters)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('location_version', description="Filter the results by the version of Location")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:stix_id>", detail=False)
    def retrieve_objects(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object(stix_id, version_param='location_version')
    
      
    @extend_schema(
            parameters=[
                OpenApiParameter('location_version', description="Filter the results by the version of Location")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:stix_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object(stix_id, relationship_mode=True, version_param='location_version')
        
    @extend_schema(
        summary="See available Location versions",
        description=textwrap.dedent(
            """
            It is possible to import multiple versions of Location using the POST Location endpoint. By default, all endpoints will only return the latest version of Location objects (which generally suits most use-cases).

            This endpoint allows you to see all imported versions of Location available to use, and which version is the latest (the default version for the objects returned).

            Note, to search in the database you can use the `_stix2arango_note` property and the value `version=XXXXXXX" e.g. `version=59da722`.
            """
            ),
        )
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer)
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_mitre_versions()
        
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:stix_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_modified_versions(stix_id)


@extend_schema_view(
    create=extend_schema(
        responses={
                    201: OpenApiResponse(
                        serializers.JobSerializer,
                        examples=[
                            OpenApiExample(
                                "",
                                value={
                                    "id": "85e78220-6387-4be1-81ea-b8373c89aa92",
                                    "type": "disarm-update",
                                    "state": "pending",
                                    "errors": [],
                                    "run_datetime": "2024-10-25T10:39:25.925090Z",
                                    "completion_time": "2024-10-25T10:39:41.551515Z",
                                    "parameters": {
                                        "version": "4_15"
                                    }
                                },
                            )
                        ],
                    ), 400: DEFAULT_400_ERROR
                },
        request=serializers.MitreTaskSerializer,
        summary="Download MITRE DISARM objects",
        description=textwrap.dedent(
            """
            Use this data to update DISARM records. [More information about MITRE DISARM here](https://disarm.mitre.org/).

            The following key/values are accepted in the body of the request:

            * `version` (required): the version of DISARM you want to download in the format `N_N`, e.g. `1_5` for `1.5`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_disarm.py#L7).
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Search and filter MITRE DISARM objects',
        description=textwrap.dedent(
            """
            Search and filter MITRE DISARM objects.

            The following STIX object types can be returned in this response:

            * `weakness`: represent the DISARM object
            * `grouping`: groups the DISARM object by external groupings, [as shown here](https://disarm.mitre.org/data/index.html).
            * `identity`: the disarm2stix identity
            * `marking-definitions`: for disarm2stix and TLPs (v2)
            """
        ),
        filters=True,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_objects=extend_schema(
        summary='Get a DISARM object',
        description=textwrap.dedent(
            """
            Get an DISARM object by its ID (e.g. `TA05` `TA01`).

            If you do not know the ID of the object you can use the GET MITRE DISARM Objects endpoint to find it.
            """
        ),
        filters=False,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    object_versions=extend_schema(
        summary="See all versions of the DISARM object",
        description=textwrap.dedent(
            """
            This endpoint will show the STIX versions of the object (`modified` property) and what DISARM versions it appears in.

            The data returned is useful to see when and object has changed.
            """
        ),
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get the Relationships linked to MITRE DISARM Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the DISARM object is found as a `source_ref` or a `target_ref`.

            If you want to see an overview of how MITRE DISARM objects are linked, [see this diagram](https://miro.com/app/board/uXjVKpOg6bM=/).

            MITRE DISARM objects can also be `source_ref` to CAPEC objects. Requires POST arango-cti-processor request using `disarm-capec` mode for this data to show.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship'), 400: DEFAULT_400_ERROR},
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters(),
    ),
    bundle=extend_schema(
        summary='Generate a bundle linked to MITRE DISARM Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the DISARM object is found as a `source_ref`.

            If you want to see an overview of how MITRE DISARM objects are linked, [see this diagram](https://miro.com/app/board/uXjVKpOg6bM=/).
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema(), 400: DEFAULT_400_ERROR},
        parameters=BUNDLE_PARAMS,
    ),
)  
class DisarmView(viewsets.ViewSet):
    openapi_tags = ["DISARM"]
    lookup_url_kwarg = 'disarm_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `x-mitre-tactic--2c0826a4-1598-5909-810a-792dda66651d`, `attack-pattern--60877675-df30-5140-98b0-1b61a80c8171`)'),
        OpenApiParameter('disarm_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The DISARM ID, e.g `TA05`, `TA01`'),
    ]
    arango_collection = 'disarm_vertex_collection'
    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `x-mitre-tactic--2c0826a4-1598-5909-810a-792dda66651d`, `attack-pattern--60877675-df30-5140-98b0-1b61a80c8171`.')
        disarm_id = BaseCSVFilter(help_text='Filter the results by the DISARM ID of the object. e.g. `TA05` `TA01`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in DISARM_TYPES], help_text='Filter the results by STIX Object type.')
        disarm_version = CharFilter(help_text="By default only the latest DISARM version objects will be returned. You can enter a specific DISARM version here. e.g. `1.5`. You can get a full list of versions on the GET DISARM versions endpoint.")

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.DISARM_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_weakness_or_capec_objects(types=DISARM_TYPES, lookup_kwarg=self.lookup_url_kwarg)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('disarm_version', description="By default only the latest DISARM version objects will be returned. You can enter a specific DISARM version here. e.g. `1.5`. You can get a full list of versions on the GET DISARM versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:disarm_id>", detail=False)
    def retrieve_objects(self, request, *args, disarm_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(disarm_id)
        
    
    @extend_schema(
            parameters=[
                OpenApiParameter('disarm_version', description="By default only the latest DISARM version objects will be returned. You can enter a specific DISARM version here. e.g. `1.5`. You can get a full list of versions on the GET DISARM versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:disarm_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, disarm_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(disarm_id, relationship_mode=True)    
    
    @extend_schema(
            parameters=[
                OpenApiParameter('disarm_version', description="By default only the latest DISARM version objects will be returned. You can enter a specific DISARM version here. e.g. `1.5`. You can get a full list of versions on the GET DISARM versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:disarm_id>/bundle", detail=False)
    def bundle(self, request, *args, disarm_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(disarm_id, bundle=True)
        
    @extend_schema(
        summary="See available DISARM versions",
        description=textwrap.dedent(
            """
            It is possible to import multiple versions of DISARM using the POST MITRE DISARM endpoint. By default, all endpoints will only return the latest version of DISARM objects (which generally suits most use-cases).

            This endpoint allows you to see all imported versions of MITRE DISARM available to use, and which version is the latest (the default version for the objects returned).

            Note, to search in the database you can use the `_stix2arango_note` property and the value `version=N_N" e.g. `version=1_5` for `1.5`.
            """
            ),
        )
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer)
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_mitre_versions()
        
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:disarm_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, disarm_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_mitre_modified_versions(disarm_id, source_name='DISARM')
