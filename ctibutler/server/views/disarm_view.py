import textwrap
from rest_framework import viewsets, status, decorators
from django_filters.rest_framework import FilterSet, DjangoFilterBackend, ChoiceFilter, CharFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from ctibutler.server.arango_helpers import ArangoDBHelper, DISARM_TYPES, DISARM_FORMS, CTI_SORT_FIELDS
from ctibutler.server.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR
from ctibutler.server.utils import Pagination, Response
from ctibutler.worker.tasks import new_task
from ctibutler.server import models
from ctibutler.server import serializers
from django_filters import BaseCSVFilter

from .commons import TruncateView, ChoiceCSVFilter, BUNDLE_PARAMS


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
        responses={200: ArangoDBHelper.get_paginated_response_schema(), 400: DEFAULT_400_ERROR, 404: DEFAULT_404_ERROR},
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
        text = CharFilter(help_text='Filter the results by the `name` and `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter results by `name`. Is wildcard so `evi` will match `revil`, `evil`, etc.')
        types = ChoiceCSVFilter(choices=[(f,f) for f in DISARM_TYPES], help_text='Filter the results by STIX Object type.')
        disarm_version = CharFilter(help_text="By default only the latest DISARM version objects will be returned. You can enter a specific DISARM version here. e.g. `1.5`. You can get a full list of versions on the GET DISARM versions endpoint.")
        disarm_type = ChoiceCSVFilter(choices=[(f,f) for f in DISARM_FORMS], help_text='Filter the results by DISARM Object type.')
        SORT_FIELDS = CTI_SORT_FIELDS+['disarm_id_ascending', 'disarm_id_descending']
        sort = ChoiceFilter(choices=[(f,f) for f in SORT_FIELDS], help_text="sort by object property/field")

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
