"""ATT&CK View for handling ATT&CK framework objects."""
import re
import textwrap
from rest_framework import viewsets, status, decorators
from rest_framework.response import Response

from django_filters.rest_framework import FilterSet, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter, BooleanFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from ctibutler.server.arango_helpers import ATTACK_SORT_FIELDS, ArangoDBHelper, ATTACK_TYPES, ATTACK_FORMS
from ctibutler.server.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR
from ctibutler.server.tie import ExtractedWalsRecommender
from ctibutler.server.utils import Pagination, Response
from ctibutler.worker.tasks import new_task
from ctibutler.server import models
from ctibutler.server import serializers

from .commons import TruncateView, ChoiceCSVFilter, REVOKED_AND_DEPRECATED_PARAMS, BUNDLE_PARAMS


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
            400: DEFAULT_400_ERROR, 404: DEFAULT_404_ERROR,
            
        },
        parameters=BUNDLE_PARAMS,
    ),
    navigator=extend_schema(
        responses={
            200: serializers.AttackNavigatorSerializer,
            400: DEFAULT_400_ERROR,
        },
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
        text = CharFilter(help_text='Filter the results by the `name` and `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        types = ChoiceCSVFilter(choices=[(f,f) for f in ATTACK_TYPES], help_text='Filter the results by STIX Object type.')
        attack_version = CharFilter(help_text="By default only the latest ATT&CK version objects will be returned. You can enter a specific ATT&CK version here. e.g. `13.1`. You can get a full list of versions on the GET ATT&CK versions endpoint.")
        include_revoked = BooleanFilter(help_text="By default all objects with `revoked` are ignored. Set this to `true` to include them.")
        include_deprecated = BooleanFilter(help_text="By default all objects with `x_mitre_deprecated` are ignored. Set this to `true` to include them.")
        alias = CharFilter(help_text='Filter the results by the `x_mitre_aliases` property of the object. Search is a wildcard, so `sun` will return all objects with x_mitre_aliases that contains the string `sun`, e.g `SUNBURST`.')
        attack_type = ChoiceCSVFilter(choices=[(f,f) for f in ATTACK_FORMS], help_text='Filter the results by Attack Object type.')
        sort = ChoiceFilter(choices=[(f,f) for f in ATTACK_SORT_FIELDS], help_text="sort by object property/field")
        name = CharFilter(help_text='Filter results by `name`. Is wildcard so `evi` will match `revil`, `evil`, etc.')

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
    
    @extend_schema(
            parameters=[
                OpenApiParameter('attack_version', description="By default only the latest ATT&CK version objects will be returned. You can enter a specific ATT&CK version here. e.g. `13.1`. You can get a full list of versions on the GET ATT&CK versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>/navigator", detail=False)
    def navigator(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_object_by_external_id(attack_id, self.lookup_url_kwarg.replace('_id', '_version'), revokable=True, nav_mode=True)

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
            navigator=extend_schema(
                summary=f"Get navigator layer file for MITRE ATT&CK {matrix_name_human} Object",
                description=textwrap.dedent(
                    """
                    This endpoint will return a [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer file for the chosen object.

                    Only the following object types are supported to generate a layer file:

                    * Software (`SNNNN`, `tool`, `malware`)
                    * Groups (`GNNNN`, `intrusion-set`)
                    * Campaigns (`CNNNN`, `campaign`)
                    * Mitigations (`MNNNN`, `course-of-action`)
                    * Assets (`ANNNN`, `x-mitre-asset`)
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
