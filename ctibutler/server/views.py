import logging
import re
from django.conf import settings
import requests
from rest_framework import viewsets, status, decorators, exceptions, parsers

from ctibutler.server.arango_helpers import ATLAS_FORMS, ATLAS_TYPES, CTI_SORT_FIELDS, CWE_TYPES, DISARM_FORMS, DISARM_TYPES, KNOWLEDGE_BASE_TO_COLLECTION_MAPPING, LOCATION_TYPES, SEMANTIC_SEARCH_SORT_FIELDS, SEMANTIC_SEARCH_TYPES, ArangoDBHelper, ATTACK_TYPES, ATTACK_FORMS, CAPEC_TYPES, LOCATION_SUBTYPES
from ctibutler.server.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR
from ctibutler.server.tie import ExtractedWalsRecommender
from ctibutler.server.utils import Pagination, Response, Ordering
from ctibutler.worker.tasks import new_task
from ctibutler.server import models
from ctibutler.server import serializers
from django_filters.rest_framework import FilterSet, Filter, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter, BooleanFilter, BaseInFilter
from django_filters.fields import ChoiceField
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes
# Create your views here.

from drf_spectacular.views import SpectacularAPIView
from rest_framework.response import Response

import textwrap

class ChoiceCSVFilter(BaseCSVFilter):
    field_class = ChoiceField

REVOKED_AND_DEPRECATED_PARAMS = [
    OpenApiParameter('include_revoked', type=OpenApiTypes.BOOL, description="By default all objects with `revoked` are ignored. Set this to `true` to include them."),
    OpenApiParameter('include_deprecated', type=OpenApiTypes.BOOL, description="By default all objects with `x_mitre_deprecated` are ignored. Set this to `true` to include them."),
]
BUNDLE_PARAMS =  ArangoDBHelper.get_schema_operation_parameters()+ [
    OpenApiParameter(
        "include_embedded_refs",
        description=textwrap.dedent(
            """
            If `ignore_embedded_relationships` is set to `false` in the POST request to download data, stix2arango will create SROS for embedded relationships (e.g. from `created_by_refs`). You can choose to show them (`true`) or hide them (`false`) using this parameter. Default value if not passed is `true`. If set to `true` then the objects referenced in the embedded refs relationships will not be shown. This is an arango_cti_processor setting.
            """
        ),
        type=OpenApiTypes.BOOL
    ),
    OpenApiParameter(
        "types",
        description="Only show objects of selected types",
        enum=[
            "relationship",
            "identity",
            "location",
            "marking-definition",
            "attack-pattern",
            "course-of-action",
            "campaign",
            "intrusion-set",
            "malware",
            "x-mitre-asset",
            "x-mitre-collection",
            "x-mitre-data-component",
            "x-mitre-data-source",
            "x-mitre-matrix",
            "x-mitre-tactic",
            "tool",
            "extension-definition",
            "grouping",
            "weakness"
        ],
        explode=False,
        style="form",
        many=True,
    ),
]


class TruncateView:
    parser_classes = [parsers.JSONParser]
    collection_to_truncate = None
    bucket_name = ""
    @extend_schema(
            summary="Truncate all collection associated with this endpoint",
            description="Truncates all collection associated with this endpoint",
            responses={204: {}},
    )
    @decorators.action(detail=False, methods=['DELETE'])
    def truncate(self, request):
        db = ArangoDBHelper('', request).db
        try:
            for suffix in ['vertex', 'edge']:
                collection_name = f'{self.collection_to_truncate}_{suffix}_collection'
                logging.info('%s: truncating %s', self.__class__.__name__, collection_name)
                collection_ = db.collection(collection_name)
                collection_.truncate()
                logging.info('%s: collection `%s` truncated', self.__class__.__name__, collection_name)
        except Exception as e:
            logging.exception("%s: truncation failed", self.__class__.__name__)
            raise exceptions.APIException("the server cannot execute this request")
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @property
    def bucket_path(self):
        return getattr(settings, self.bucket_name.upper()+'_BUCKET_ROOT_PATH', "")
    
    @extend_schema(
            summary="List all versions available to install",
            description=textwrap.dedent(
                    """
                    This endpoint will query the available versions of the knowledgebase available to download on `https://downloads.ctibutler.com`.

                    Use the response of this endpoint to install the versions on the download endpoint.
                    """
            ),
            responses={200: {"type": "array", "items": {"type": "string"}}},
    )
    @decorators.action(detail=False, methods=['GET'], url_path="versions/available")
    def versions_available(self, request):
        url = self.bucket_path.strip('/') + "/version.txt"
        resp = requests.get(url)
        assert resp.status_code == 200, resp.url
        versions = [s.strip() for s in resp.text.splitlines()]
        return Response(versions)


@extend_schema_view(
    create=extend_schema(),
    list_objects=extend_schema(
        responses={
            200: serializers.StixObjectsSerializer(many=True),
            400: DEFAULT_400_ERROR,
        },
        filters=True,
    ),
    retrieve_objects=extend_schema(
        responses={
            200: serializers.StixObjectsSerializer(many=True),
            400: DEFAULT_400_ERROR,
        },
        parameters=REVOKED_AND_DEPRECATED_PARAMS,
    ),
    retrieve_object_relationships=extend_schema(
        responses={
            200: ArangoDBHelper.get_paginated_response_schema(
                "relationships", "relationship"
            ),
            400: DEFAULT_400_ERROR,
        },
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters()
        + REVOKED_AND_DEPRECATED_PARAMS,
    ),
    bundle=extend_schema(
        responses={
            200: ArangoDBHelper.get_paginated_response_schema(),
            400: DEFAULT_400_ERROR,
        },
        parameters=BUNDLE_PARAMS,
    ),
    tie=extend_schema(
        responses={
            200: serializers.TIEResponseSerializer,
            400: DEFAULT_400_ERROR,
        },
        parameters=[
            OpenApiParameter(
                "technique_ids",
                description="Techniques generate prediction from. Pass in format `T1548,T1134`",
                explode=False,
                style="form",
                many=True,
            ),
        ],
    ),
)
class AttackView(TruncateView, viewsets.ViewSet):
    openapi_tags = ["ATT&CK"]
    lookup_url_kwarg = 'attack_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`, `malware--04227b24-7817-4de1-9050-b7b1b57f5866`)'),
        OpenApiParameter('attack_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The ATT&CK ID, e.g `T1659`, `TA0043`, `S0066` OR the STIX ID e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`'),
    ]

    filter_backends = [DjangoFilterBackend]
    MATRIX_TYPES = ["mobile", "ics", "enterprise"]
    @property
    def matrix(self):
        m: re.Match = re.search(r"/attack-(\w+)/", self.request.path)
        return m.group(1)

    @property
    def bucket_name(self):
        return f"ATTACK_{self.matrix}"

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`, `malware--04227b24-7817-4de1-9050-b7b1b57f5866`.')
        attack_id = BaseCSVFilter(help_text='The ATT&CK IDs of the object wanted. e.g. `T1659`, `TA0043`, `S0066` OR the STIX ID e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        types = ChoiceCSVFilter(choices=[(f,f) for f in ATTACK_TYPES], help_text='Filter the results by STIX Object type.')
        attack_version = CharFilter(help_text="By default only the latest ATT&CK version objects will be returned. You can enter a specific ATT&CK version here. e.g. `13.1`. You can get a full list of versions on the GET ATT&CK versions endpoint.")
        include_revoked = BooleanFilter(help_text="By default all objects with `revoked` are ignored. Set this to `true` to include them.")
        include_deprecated = BooleanFilter(help_text="By default all objects with `x_mitre_deprecated` are ignored. Set this to `true` to include them.")
        alias = CharFilter(help_text='Filter the results by the `x_mitre_aliases` property of the object. Search is a wildcard, so `sun` will return all objects with x_mitre_aliases that contains the string `sun`, e.g `SUNBURST`.')
        attack_type = ChoiceFilter(choices=[(f,f) for f in ATTACK_FORMS], help_text='Filter the results by Attack Object type.')
        sort = ChoiceFilter(choices=[(f,f) for f in CTI_SORT_FIELDS], help_text="sort by object property/field")

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
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_object_by_external_id(attack_id, self.lookup_url_kwarg.replace('_id', '_version'), revokable=True)

    @extend_schema(
            parameters=[
                OpenApiParameter('attack_version', description="By default only the latest ATT&CK version objects will be returned. You can enter a specific ATT&CK version here. e.g. `13.1`. You can get a full list of versions on the GET ATT&CK versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_object_by_external_id(attack_id, self.lookup_url_kwarg.replace('_id', '_version'), relationship_mode=True, revokable=True)

    @extend_schema(
            parameters=[
                OpenApiParameter('attack_version', description="By default only the latest ATT&CK version objects will be returned. You can enter a specific ATT&CK version here. e.g. `13.1`. You can get a full list of versions on the GET ATT&CK versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>/bundle", detail=False)
    def bundle(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_object_by_external_id(attack_id, self.lookup_url_kwarg.replace('_id', '_version'), revokable=True, bundle=True)

    @extend_schema()
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer, url_path="versions/installed")
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_mitre_versions()

    @extend_schema(filters=False, parameters=REVOKED_AND_DEPRECATED_PARAMS)
    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_mitre_modified_versions(attack_id)

    def get_tie(self, matrix, techniques):
        model = ExtractedWalsRecommender()
        version = '15_0'
        model.load(f"tie_models/{matrix}/attack-{matrix}-{version}.npz")
        return dict(model.make_predictions(techniques))
        
    
    @decorators.action(detail=False, methods=["GET"])
    def tie(self, request):
        techniques = [t for t in request.GET.get('technique_ids', '').split(',') if t]
        query = request._request.GET = request.GET.copy()
        scores = self.get_tie(
            self.matrix,
            techniques,
        )
        query['attack_id'] = ','.join(scores)
        objects = self.list_objects(request=request).data['objects']
        return Response(dict(scores=scores, objects=objects))
    
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
                    400: DEFAULT_400_ERROR,
                },
                request=serializers.MitreTaskSerializer,
                summary=f"Download MITRE ATT&CK {matrix_name_human} Objects",
                description=textwrap.dedent(
                    """
                    Use this endpoint to update MITRE ATT&CK records. [More information about MITRE ATT&CK here](https://attack.mitre.org/).

                    The following key/values are accepted in the body of the request:

                    * `version` (required): the version of ATT&CK you want to download in the format `N_N`, e.g. `16_0` for `16.0`. You can see all versions installed and available to download on the version endpoints.
                    * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them. This includes all objects (use ignore SRO/SMO for more granular options). This is a stix2arango setting.
                    * `ignore_embedded_relationships_sro` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). Default is `false`. This is a stix2arango setting.
                    * `ignore_embedded_relationships_smo` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). Default is `false`. This is a stix2arango setting.

                    The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [dogesec](https://www.dogesec.com/) team).

                    Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
                    """
                ),
            ),
            list_objects=extend_schema(
                summary=f"Search and filter MITRE ATT&CK {matrix_name_human} objects",
                description=textwrap.dedent(
                    """
                    Search and filter MITRE ATT&CK objects.
                    """
                ),
                filters=True,
            ),
            retrieve_objects=extend_schema(
                summary=f"Get a specific MITRE ATT&CK {matrix_name_human} object by its ID",
                description=textwrap.dedent(
                    """
                    Get a MITRE ATT&CK object by its MITRE ATT&CK ID (e.g. `T1659`, `TA0043`, `S0066`) OR the STIX ID e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`.

                    If you do not know the ID of the object you can use the GET MITRE ATT&CK Objects endpoint to find it.
                    """
                ),
                filters=False,
            ),
            versions=extend_schema(
                summary=f"Get a list of MITRE ATT&CK {matrix_name_human} versions stored in the database",
                description=textwrap.dedent(
                    """
                    It is possible to install multiple versions of ATT&CK using the POST MITRE ATT&CK endpoint. By default, all endpoints will only return the latest version of ATT&CK objects (which generally suits most use-cases).

                    This endpoint allows you to see all installed versions of MITRE ATT&CK available to use, and which version is the latest (the default version for the objects returned).
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
                summary=f"Get all objects linked to the MITRE ATT&CK {matrix_name_human} Object",
                description=textwrap.dedent(
                    """
                    This endpoint will return all the STIX objects referenced in `relationship` objects where the source object is found as a `source_ref` or `target_ref`.

                    It will also return the `relationship` objects too, allowing you to easily import the entire network graph of objects into other tools.

                    If you want to see an overview of how MITRE ATT&CK objects are linked, [see this diagram](https://miro.com/app/board/uXjVKBgHZ2I=/).
                    """
                ),
            ),
            truncate=extend_schema(
                summary=f"Wipe the collections holding MITRE ATT&CK {matrix_name_human} objects",
                description=textwrap.dedent(
                    f"""
                    Wipe the ArangoDB Collections `mitre_attack_{matrix_name_human}_vertex_collection` and `mitre_attack_{matrix_name_human}_edge_collection` holding MITRE ATT&CK {matrix_name_human} objects.

                    **WARNING**: This will delete all objects in these collections, which will mean all MITRE ATT&CK {matrix_name_human} versions stored will be removed.
                    """
                ),
            ),
            tie=extend_schema(
                summary=f"Suggest techniques an adversary is likely to have used based on a set of observed techniques",
                description=textwrap.dedent(
                    f"""
                    Pass a list of ATT&CK {matrix_name_human} Techniques to predict other Techniques likely to be employed in an attack.

                    This uses the [MITRE CTID Technique Inference Engine](https://center-for-threat-informed-defense.github.io/technique-inference-engine/) using the [WalsRecommender model](https://github.com/center-for-threat-informed-defense/technique-inference-engine/blob/main/src/tie/recommender/wals_recommender.py) where a pretrained model (on Enterprise v15.0) is loaded from file (that is downloaded at CTI Butler install time).
                    """
                ),
            ),
        )
        class TempAttackView(cls):
            matrix = matrix_name
            openapi_tags = [f"ATT&CK {matrix_name_human}"]
            collection_to_truncate = f"mitre_attack_{matrix}"

            if matrix_name != "enterprise":
                tie = None
                

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

            * `version` (required): the version of CWE you want to download in the format `N_N`, e.g. `4_16` for `4.16`. You can see all versions installed and available to download on the version endpoints.
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them. This includes all objects (use ignore SRO/SMO for more granular options). This is a stix2arango setting.
            * `ignore_embedded_relationships_sro` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). Default is `false`. This is a stix2arango setting.
            * `ignore_embedded_relationships_smo` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). Default is `false`. This is a stix2arango setting.
            
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [dogesec](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Search and filter MITRE CWE objects',
        description=textwrap.dedent(
            """
            Search and filter MITRE CWE objects.
            """
        ),
        filters=True,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_objects=extend_schema(
        summary='Get a CWE object',
        description=textwrap.dedent(
            """
            Get an CWE object by its ID (e.g. `CWE-242` `CWE-250`) OR the STIX ID `weakness--f3496f30-5625-5b6d-8297-ddc074fb26c2`.

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
        summary='Get all objects linked to the MITRE CWE Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX objects referenced in `relationship` objects where the source object is found as a `source_ref` or `target_ref`.

            It will also return the `relationship` objects too, allowing you to easily import the entire network graph of objects into other tools.

            If you want to see an overview of how MITRE CWE objects are linked, [see this diagram](https://miro.com/app/board/uXjVKpOg6bM=/).

            MITRE CWE objects can also be `source_ref` to CAPEC objects. Requires POST arango-cti-processor request using `cwe-capec` mode for this data to show.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema(), 400: DEFAULT_400_ERROR},
        parameters=BUNDLE_PARAMS,
    ),
    truncate=extend_schema(
        summary=f"Wipe the collections holding MITRE CWE objects",
        description=textwrap.dedent(
            f"""
            Wipe the ArangoDB Collections `mitre_cwe_vertex_collection` and `mitre_cwe_edge_collection` holding MITRE CWE objects.

            **WARNING**: This will delete all objects in these collections, which will mean all MITRE CWE versions stored will be removed.
            """
        ),
    ),
)  
class CweView(TruncateView, viewsets.ViewSet):
    openapi_tags = ["CWE"]
    collection_to_truncate = 'mitre_cwe'
    lookup_url_kwarg = 'cwe_id'
    bucket_name = 'cwe'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `weakness--f3496f30-5625-5b6d-8297-ddc074fb26c2`, `grouping--000ee024-ad9c-5557-8d49-2573a8e788d2`)'),
        OpenApiParameter('cwe_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CWE ID, e.g `CWE-242`, `CWE-250` OR the STIX ID `weakness--f3496f30-5625-5b6d-8297-ddc074fb26c2`.'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `weakness--f3496f30-5625-5b6d-8297-ddc074fb26c2`, `grouping--000ee024-ad9c-5557-8d49-2573a8e788d2`.')
        cwe_id = BaseCSVFilter(help_text='Filter the results by the CWE ID of the object. e.g. `CWE-242` `CWE-250`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        types = ChoiceCSVFilter(choices=[(f,f) for f in CWE_TYPES], help_text='Filter the results by STIX Object type.')
        cwe_version = CharFilter(help_text="By default only the latest CWE version objects will be returned. You can enter a specific CWE version here. e.g. `4.13`. You can get a full list of versions on the GET CWE versions endpoint.")
        sort = ChoiceFilter(choices=[(f,f) for f in CTI_SORT_FIELDS], help_text="sort by object property/field")

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CWE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_weakness_or_capec_objects(lookup_kwarg=self.lookup_url_kwarg)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('cwe_version', description="By default only the latest CWE version objects will be returned. You can enter a specific CWE version here. e.g. `4.13`. You can get a full list of versions on the GET CWE versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>", detail=False)
    def retrieve_objects(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_object_by_external_id(cwe_id, self.lookup_url_kwarg.replace('_id', '_version'))
        
    
    @extend_schema(
            parameters=[
                OpenApiParameter('cwe_version', description="By default only the latest CWE version objects will be returned. You can enter a specific CWE version here. e.g. `4.13`. You can get a full list of versions on the GET CWE versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_object_by_external_id(cwe_id, self.lookup_url_kwarg.replace('_id', '_version'), relationship_mode=True)        
    
    @extend_schema(
            parameters=[
                OpenApiParameter('cwe_version', description="By default only the latest CWE version objects will be returned. You can enter a specific CWE version here. e.g. `4.13`. You can get a full list of versions on the GET CWE versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>/bundle", detail=False)
    def bundle(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_object_by_external_id(cwe_id, self.lookup_url_kwarg.replace('_id', '_version'), bundle=True)
        
    @extend_schema(
        summary="See installed CWE versions",
        description=textwrap.dedent(
            """
            It is possible to install multiple versions of CWE using the POST MITRE CWE endpoint. By default, all endpoints will only return the latest version of CWE objects (which generally suits most use-cases).

            This endpoint allows you to see all installed versions of MITRE CWE available to use, and which version is the latest (the default version for the objects returned).
            """
            ),
        )
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer, url_path="versions/installed")
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

            * `version` (required): the version of CAPEC you want to download in the format `N_N`, e.g. `3_9` for `3.9`. You can see all versions installed and available to download on the version endpoints.
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them. This includes all objects (use ignore SRO/SMO for more granular options). This is a stix2arango setting.
            * `ignore_embedded_relationships_sro` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). Default is `false`. This is a stix2arango setting.
            * `ignore_embedded_relationships_smo` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). Default is `false`. This is a stix2arango setting.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [dogesec](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Search and filter MITRE CAPEC objects',
        description=textwrap.dedent(
            """
            Search and filter MITRE CAPEC objects.      
            """
        ),
        filters=True,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_objects=extend_schema(
        summary='Get a CAPEC object',
        description=textwrap.dedent(
            """
            Get a CAPEC object by its ID (e.g. `CAPEC-112`, `CAPEC-699`) OR the STIX ID e.g. `attack-pattern--92cdcd3d-d734-4442-afc3-4599f261498b`).

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
        summary='Get all objects linked to the MITRE CAPEC Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX objects referenced in `relationship` objects where the source object is found as a `source_ref` or `target_ref`.

            It will also return the `relationship` objects too, allowing you to easily import the entire network graph of objects into other tools.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema(), 400: DEFAULT_400_ERROR},
        parameters=BUNDLE_PARAMS,
    ),
    truncate=extend_schema(
        summary=f"Wipe the collections holding MITRE CAPEC objects",
        description=textwrap.dedent(
            f"""
            Wipe the ArangoDB Collections `mitre_capec_vertex_collection` and `mitre_capec_edge_collection` holding MITRE CAPEC objects.

            **WARNING**: This will delete all objects in these collections, which will mean all MITRE CAPEC versions stored will be removed.
            """
        ),
    ),
)
class CapecView(TruncateView, viewsets.ViewSet):
    openapi_tags = ["CAPEC"]
    collection_to_truncate = 'mitre_capec'
    lookup_url_kwarg = 'capec_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6`, `course-of-action--0002fa37-9334-41e2-971a-cc8cab6c00c4`)'),
        OpenApiParameter('capec_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CAPEC ID, e.g `CAPEC-112`, `CAPEC-699` OR the STIX ID e.g. `attack-pattern--92cdcd3d-d734-4442-afc3-4599f261498b`)'),
    ]

    filter_backends = [DjangoFilterBackend]
    bucket_name = 'capec'

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6`, `course-of-action--0002fa37-9334-41e2-971a-cc8cab6c00c4`.')
        capec_id = BaseCSVFilter(help_text='Filter the results by the CAPEC ID of the object. e.g. `CAPEC-112`, `CAPEC-699`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        types = ChoiceCSVFilter(choices=[(f,f) for f in CAPEC_TYPES], help_text='Filter the results by STIX Object type.')
        capec_version = CharFilter(help_text="By default only the latest CAPEC version objects will be returned. You can enter a specific CAPEC version here. e.g. `3.7`. You can get a full list of versions on the GET CAPEC versions endpoint.")
        sort = ChoiceFilter(choices=[(f,f) for f in CTI_SORT_FIELDS], help_text="sort by object property/field")

    
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
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_object_by_external_id(capec_id, self.lookup_url_kwarg.replace('_id', '_version'))
    
    @extend_schema(
            parameters=[
                OpenApiParameter('capec_version', description="By default only the latest CAPEC version objects will be returned. You can enter a specific CAPEC version here. e.g. `3.7`. You can get a full list of versions on the GET CAPEC versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_object_by_external_id(capec_id, self.lookup_url_kwarg.replace('_id', '_version'), relationship_mode=True)
        
    @extend_schema(
            parameters=[
                OpenApiParameter('capec_version', description="By default only the latest CAPEC version objects will be returned. You can enter a specific CAPEC version here. e.g. `3.7`. You can get a full list of versions on the GET CAPEC versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>/bundle", detail=False)
    def bundle(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_object_by_external_id(capec_id, self.lookup_url_kwarg.replace('_id', '_version'), bundle=True)
    
    @extend_schema(
        summary="Get a list of CAPEC versions stored in the database",
        description=textwrap.dedent(
            """
            It is possible to install multiple versions of CAPEC using the POST MITRE CAPEC endpoint. By default, all endpoints will only return the latest version of CAPEC objects (which generally suits most use-cases).

            This endpoint allows you to see all installed versions of MITRE CAPEC available to use, and which version is the latest (the default version for the objects returned).
            """
            ),
        )
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer, url_path="versions/installed")
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

            * `ignore_embedded_relationships` (optional - default: `false`): arango_cti_processor generates SROs to link knowledge-bases. These SROs have embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them. This is an arango_cti_processor setting.
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
        serializers.ACPSerializer(data=request.data).is_valid(raise_exception=True)
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
        
        types = ChoiceCSVFilter(
            help_text='Filter the results by the type of Job',
            choices=get_type_choices(), method='filter_type'
        )
        state = Filter(help_text='Filter the results by the state of the Job')

        def filter_type(self, qs, field_name, value: str):
            query = dict(type=value)
            if '--' in value:
                type, mode = value.split('--')
                query = dict(type=type, parameters__mode=mode)
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

            * `version` (required): the version of ATLAS you want to download in the format `N_N_N`, e.g. `4_7_0` for `4.7.0`. You can see all versions installed and available to download on the version endpoints.
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them. This includes all objects (use ignore SRO/SMO for more granular options). This is a stix2arango setting.
            * `ignore_embedded_relationships_sro` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). Default is `false`. This is a stix2arango setting.
            * `ignore_embedded_relationships_smo` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). Default is `false`. This is a stix2arango setting.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [dogesec](https://www.dogesec.com/) team).

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
            Get an ATLAS object by its ID (e.g. `AML.TA0002`, `AML.T0000`) OR its STIX ID (e.g. `attack-pattern--f09d9beb-4cb5-4094-83b6-e46bedc8a20e`).

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
        summary='Get all objects linked to the MITRE ATLAS Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX objects referenced in `relationship` objects where the source object is found as a `source_ref` or `target_ref`.

            It will also return the `relationship` objects too, allowing you to easily import the entire network graph of objects into other tools.
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
    truncate=extend_schema(
        summary=f"Wipe the collections holding ATLAS objects",
        description=textwrap.dedent(
            f"""
            Wipe the ArangoDB Collections `mitre_atlas_vertex_collection` and `mitre_atlas_edge_collection` holding MITRE ATLAS objects.

            **WARNING**: This will delete all objects in these collections, which will mean all MITRE ATLAS versions stored will be removed.
            """
        ),
    ),
)  
class AtlasView(TruncateView, viewsets.ViewSet):
    openapi_tags = ["ATLAS"]
    lookup_url_kwarg = 'atlas_id'
    collection_to_truncate = 'mitre_atlas'
    bucket_name = 'atlas'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `attack-pattern--64db2878-ae36-46ab-b47a-f71fff575aba`, `x-mitre-tactic--6b232c1e-ada7-4cd4-b538-7a1ef6193e2f`)'),
        OpenApiParameter('atlas_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The ATLAS ID, e.g `AML.TA0002`, `AML.T0000` OR its STIX ID e.g. `attack-pattern--f09d9beb-4cb5-4094-83b6-e46bedc8a20e`'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `attack-pattern--64db2878-ae36-46ab-b47a-f71fff575aba`, `x-mitre-tactic--6b232c1e-ada7-4cd4-b538-7a1ef6193e2f`.')
        atlas_id = BaseCSVFilter(help_text='Filter the results by the ATLAS ID of the object. e.g. `AML.T0000.001`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        types = ChoiceCSVFilter(choices=[(f,f) for f in ATLAS_TYPES], help_text='Filter the results by STIX Object type.')
        atlas_version = CharFilter(help_text="By default only the latest ATLAS version objects will be returned. You can enter a specific ATLAS version here. e.g. `4.9.0`. You can get a full list of versions on the GET ATLAS versions endpoint.")
        atlas_type = ChoiceFilter(choices=[(f,f) for f in ATLAS_FORMS], help_text='Filter the results by ATLAS Object type.')
        sort = ChoiceFilter(choices=[(f,f) for f in CTI_SORT_FIELDS], help_text="sort by object property/field")

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.ATLAS_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_weakness_or_capec_objects(types=ATLAS_TYPES, lookup_kwarg=self.lookup_url_kwarg, forms=ATLAS_FORMS)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('atlas_version', description="Filter the results by the version of ATLAS")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>", detail=False)
    def retrieve_objects(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_object_by_external_id(atlas_id, self.lookup_url_kwarg.replace('_id', '_version'))    
    @extend_schema(
            parameters=[
                OpenApiParameter('atlas_version', description="Filter the results by the version of ATLAS")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_object_by_external_id(atlas_id, self.lookup_url_kwarg.replace('_id', '_version'), relationship_mode=True)
        
    @extend_schema(
            parameters=[
                OpenApiParameter('atlas_version', description="Filter the results by the version of ATLAS")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>/bundle", detail=False)
    def bundle(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_object_by_external_id(atlas_id, self.lookup_url_kwarg.replace('_id', '_version'), bundle=True)
        
    @extend_schema(
        summary="See installed ATLAS versions",
        description=textwrap.dedent(
            """
            It is possible to install multiple versions of ATLAS using the POST MITRE ATLAS endpoint. By default, all endpoints will only return the latest version of ATLAS objects (which generally suits most use-cases).

            This endpoint allows you to see all installed versions of MITRE ATLAS available to use, and which version is the latest (the default version for the objects returned).
            """
            ),
        )
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer, url_path="versions/installed")
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_mitre_versions()
        
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_atlas_vertex_collection', request).get_mitre_modified_versions(atlas_id, source_name='mitre-atlas')


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

            * `version` (required): the versions of Locations bundle you want to download in the format `N_N`, e.g. `1_0` for `1.0`. You can see all versions installed and available to download on the version endpoints.
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them. This includes all objects (use ignore SRO/SMO for more granular options). This is a stix2arango setting.
            * `ignore_embedded_relationships_sro` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). Default is `false`. This is a stix2arango setting.
            * `ignore_embedded_relationships_smo` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). Default is `false`. This is a stix2arango setting.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [dogesec](https://www.dogesec.com/) team).

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
            Get a Location object by its location2stix ID (e.g. `ZA`, `western-africa`) OR the STIX ID of the object e.g. `location--e68e76c5-60f1-506e-b495-86adb8ec0a5b`.
            
            If you do not know the ID of the object you can use the GET Locations Objects endpoint to find it.
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
        responses={200: serializers.MitreObjectVersions(many=True), 400: DEFAULT_400_ERROR},
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
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship'), 400: DEFAULT_400_ERROR},
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters(),
    ),
    bundle=extend_schema(
        summary='Get all objects linked to the  Location object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX objects referenced in `relationship` objects where the source object is found as a `source_ref` or `target_ref`.

            It will also return the `relationship` objects too, allowing you to easily import the entire network graph of objects into other tools.

            If you want to see an overview of how Location objects are linked, [see this diagram](https://miro.com/app/board/uXjVKAj06DQ=/).
            """
        ),
        filters=False,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
        parameters=BUNDLE_PARAMS,
    ),
    truncate=extend_schema(
        summary=f"Wipe the collections holding Location objects",
        description=textwrap.dedent(
            f"""
            Wipe the ArangoDB Collections `location_vertex_collection` and `location_edge_collection` holding Location objects.

            **WARNING**: This will delete all objects in these collections, which will mean all Location versions stored will be removed.
            """
        ),
    ),
)  
class LocationView(TruncateView, viewsets.ViewSet):
    openapi_tags = ["Location"]
    lookup_url_kwarg = 'location_id'
    collection_to_truncate = 'location'
    bucket_name = 'location'
    openapi_path_params = [
        # OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID of the object (e.g. `location--bc9ab5f5-cb71-5f3f-a4aa-5265053b8e68`, `location--10f646f3-2693-5a48-b544-b13b7afaa327`)'),
        OpenApiParameter('location_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The ID of the Location object (e.g. `ZA`, `western-africa`) OR the STIX ID of the object e.g. `location--e68e76c5-60f1-506e-b495-86adb8ec0a5b`'),
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
        sort = ChoiceFilter(choices=[(f,f) for f in CTI_SORT_FIELDS], help_text="sort by object property/field")

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
            more_binds['alpha3_matchers'] = [dict(source_name='alpha-3', external_id=code.upper()) for code in helper.query_as_array('alpha3_code')]
        if q := helper.query_as_array('alpha2_code'):
            more_filters.append("FILTER doc.country IN @alpha2_matchers")
            more_binds['alpha2_matchers'] = [code.upper() for code in helper.query_as_array('alpha2_code')]
        if helper.query_as_array('location_type'):
            more_filters.append("FILTER doc.external_references[? ANY FILTER CURRENT IN @location_type_matchers]")
            more_binds['location_type_matchers'] = [dict(source_name='type', external_id=code) for code in helper.query_as_array('location_type')]
        return helper.get_weakness_or_capec_objects(types=LOCATION_TYPES, lookup_kwarg=self.lookup_url_kwarg, more_binds=more_binds, more_filters=more_filters)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('location_version', description="Filter the results by the version of Location")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:location_id>", detail=False)
    def retrieve_objects(self, request, *args, location_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(location_id, self.lookup_url_kwarg.replace('_id', '_version'))
    
      
    @extend_schema(
            parameters=[
                OpenApiParameter('location_version', description="Filter the results by the version of Location")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:location_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, location_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(location_id, self.lookup_url_kwarg.replace('_id', '_version'), relationship_mode=True)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('location_version', description="Filter the results by the version of Location")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:location_id>/bundle", detail=False)
    def bundle(self, request, *args, location_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(location_id, self.lookup_url_kwarg.replace('_id', '_version'), bundle=True)
        
    @extend_schema(
        summary="See installed Location versions",
        description=textwrap.dedent(
            """
            It is possible to install multiple versions of Location using the POST Location endpoint. By default, all endpoints will only return the latest version of Location objects (which generally suits most use-cases).

            This endpoint allows you to see all installed versions of Locations available to use, and which version is the latest (the default version for the objects returned).
            """
            ),
        )
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer, url_path="versions/installed")
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_mitre_versions()
        
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:location_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, location_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_mitre_modified_versions(location_id, source_name='location2stix')

        # return ArangoDBHelper(self.arango_collection, request).get_modified_versions(location_id)


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

            * `version` (required): the version of DISARM you want to download in the format `N_N`, e.g. `1_5` for `1.5`. You can see all versions installed and available to download on the version endpoints.
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them. This includes all objects (use ignore SRO/SMO for more granular options). This is a stix2arango setting.
            * `ignore_embedded_relationships_sro` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). Default is `false`. This is a stix2arango setting.
            * `ignore_embedded_relationships_smo` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). Default is `false`. This is a stix2arango setting.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [dogesec](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Search and filter MITRE DISARM objects',
        description=textwrap.dedent(
            """
            Search and filter MITRE DISARM objects.
            """
        ),
        filters=True,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_objects=extend_schema(
        summary='Get a DISARM object',
        description=textwrap.dedent(
            """
            Get an DISARM object by its ID (e.g. `TA05` `TA01`) OR the STIX ID e.g. `attack-pattern--8ab240c2-6f7a-5c48-a4c8-3ab15b7150f3`.

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
        summary='Get all objects linked to the MITRE DISARM Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX objects referenced in `relationship` objects where the source object is found as a `source_ref` or `target_ref`.

            It will also return the `relationship` objects too, allowing you to easily import the entire network graph of objects into other tools.

            If you want to see an overview of how MITRE DISARM objects are linked, [see this diagram](https://miro.com/app/board/uXjVKpOg6bM=/).
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema(), 400: DEFAULT_400_ERROR},
        parameters=BUNDLE_PARAMS,
    ),
    truncate=extend_schema(
        summary=f"Wipe the collections holding DISARM objects",
        description=textwrap.dedent(
            f"""
            Wipe the ArangoDB Collections `disarm_vertex_collection` and `disarm_edge_collection` holding DISARM objects.

            **WARNING**: This will delete all objects in these collections, which will mean all DISARM versions stored will be removed.
            """
        ),
    ),
)  
class DisarmView(TruncateView, viewsets.ViewSet):
    openapi_tags = ["DISARM"]
    lookup_url_kwarg = 'disarm_id'
    collection_to_truncate = 'disarm'
    bucket_name = 'disarm'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `x-mitre-tactic--2c0826a4-1598-5909-810a-792dda66651d`, `attack-pattern--60877675-df30-5140-98b0-1b61a80c8171`)'),
        OpenApiParameter('disarm_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The DISARM ID, e.g `TA05`, `TA01` OR the STIX ID e.g. `attack-pattern--8ab240c2-6f7a-5c48-a4c8-3ab15b7150f3`.'),
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
        types = ChoiceCSVFilter(choices=[(f,f) for f in DISARM_TYPES], help_text='Filter the results by STIX Object type.')
        disarm_version = CharFilter(help_text="By default only the latest DISARM version objects will be returned. You can enter a specific DISARM version here. e.g. `1.5`. You can get a full list of versions on the GET DISARM versions endpoint.")
        disarm_type = ChoiceFilter(choices=[(f,f) for f in DISARM_FORMS], help_text='Filter the results by DISARM Object type.')
        sort = ChoiceFilter(choices=[(f,f) for f in CTI_SORT_FIELDS], help_text="sort by object property/field")

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.DISARM_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_weakness_or_capec_objects(types=DISARM_TYPES, lookup_kwarg=self.lookup_url_kwarg, forms=DISARM_FORMS)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('disarm_version', description="By default only the latest DISARM version objects will be returned. You can enter a specific DISARM version here. e.g. `1.5`. You can get a full list of versions on the GET DISARM versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:disarm_id>", detail=False)
    def retrieve_objects(self, request, *args, disarm_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(disarm_id, self.lookup_url_kwarg.replace('_id', '_version'))
        
    
    @extend_schema(
            parameters=[
                OpenApiParameter('disarm_version', description="By default only the latest DISARM version objects will be returned. You can enter a specific DISARM version here. e.g. `1.5`. You can get a full list of versions on the GET DISARM versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:disarm_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, disarm_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(disarm_id, self.lookup_url_kwarg.replace('_id', '_version'), relationship_mode=True)    
    
    @extend_schema(
            parameters=[
                OpenApiParameter('disarm_version', description="By default only the latest DISARM version objects will be returned. You can enter a specific DISARM version here. e.g. `1.5`. You can get a full list of versions on the GET DISARM versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:disarm_id>/bundle", detail=False)
    def bundle(self, request, *args, disarm_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(disarm_id, self.lookup_url_kwarg.replace('_id', '_version'), bundle=True)
        
    @extend_schema(
        summary="See installed DISARM versions",
        description=textwrap.dedent(
            """
            It is possible to install multiple versions of DISARM using the POST MITRE DISARM endpoint. By default, all endpoints will only return the latest version of DISARM objects (which generally suits most use-cases).

            This endpoint allows you to see all installed versions of MITRE DISARM available to use, and which version is the latest (the default version for the objects returned).
            """
            ),
        )
    @decorators.action(detail=False, methods=["GET"], serializer_class=serializers.MitreVersionsSerializer, url_path="versions/installed")
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_mitre_versions()
        
    @extend_schema(filters=False)
    @decorators.action(methods=['GET'], url_path="objects/<str:disarm_id>/versions", detail=False, serializer_class=serializers.MitreObjectVersions(many=True), pagination_class=None)
    def object_versions(self, request, *args, disarm_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_mitre_modified_versions(disarm_id, source_name='DISARM')


@extend_schema_view(
    list=extend_schema(
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
        summary="Search for objects",
        description=textwrap.dedent(
            """
            Use the endpoint to search for objects across all endpoints.

            This endpoint is particularly useful when you don't know the objects you want, or if the concept you're interested in is covered by a framework.
            """
        ),
        parameters=REVOKED_AND_DEPRECATED_PARAMS,
    )
)
class SearchView(viewsets.ViewSet):
    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")
    openapi_tags = ["Search"]
    filter_backends = [DjangoFilterBackend]
    class filterset_class(FilterSet):
        text = CharFilter(help_text='The search query. e.g `denial of service`')
        types = ChoiceCSVFilter(choices=[(f,f) for f in SEMANTIC_SEARCH_TYPES], help_text='Filter the results by STIX Object type.')
        knowledge_bases = ChoiceCSVFilter(choices=[(f, f) for f in KNOWLEDGE_BASE_TO_COLLECTION_MAPPING], help_text='Filter results by containing knowledgebase you want to search. If not passed will search all knowledgebases in CTI Butler')
        show_knowledgebase = BooleanFilter(help_text="If `true`, will add `knowledgebase_name` property to each returend object. Note, setting to `true` will break the objects in the response from being pure STIX 2.1. Default is `false`")
        sort = ChoiceFilter(choices=[(f, f) for f in SEMANTIC_SEARCH_SORT_FIELDS], help_text="attribute to sort by")
    def list(self, request, *args, **kwargs):
        return ArangoDBHelper("semantic_search_view", request).semantic_search()


@extend_schema(
    responses={204:{}},
    tags=["Server Status"],
    summary="Check if the service is running",
    description=textwrap.dedent(
        """
        If this endpoint returns a 204, the service is running as expected.
        """
        ),
    )
@decorators.api_view(["GET"])
def health_check(request):
   return Response(status=status.HTTP_204_NO_CONTENT)


class SchemaViewCached(SpectacularAPIView):
    _schema = None
    
    def _get_schema_response(self, request):
        version = self.api_version or request.version or self._get_version_parameter(request)
        if not self.__class__._schema:
            generator = self.generator_class(urlconf=self.urlconf, api_version=version, patterns=self.patterns)
            self.__class__._schema = generator.get_schema(request=request, public=self.serve_public)
        return Response(
            data=self._schema,
            headers={"Content-Disposition": f'inline; filename="{self._get_filename(request, version)}"'}
        )
