import textwrap
from rest_framework import viewsets, status, decorators
from django_filters.rest_framework import FilterSet, DjangoFilterBackend, ChoiceFilter, CharFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from ctibutler.server.arango_helpers import ArangoDBHelper, SECTORS_SORT_FIELDS
from ctibutler.server.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR
from ctibutler.server.utils import Pagination, Response
from ctibutler.worker.tasks import new_task
from ctibutler.server import models
from ctibutler.server import serializers
from django_filters import BaseCSVFilter

from .commons import TruncateView, BUNDLE_PARAMS


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
                            "type": "sector-update",
                            "state": "pending",
                            "errors": [],
                            "run_datetime": "2024-10-25T10:39:25.925090Z",
                            "completion_time": "2024-10-25T10:39:41.551515Z",
                            "parameters": {"version": "4_15"},
                        },
                    )
                ],
            ),
            400: DEFAULT_400_ERROR,
        },
        request=serializers.MitreTaskSerializer,
        summary="Download Sector objects",
        description=textwrap.dedent(
            """
            Use this data to update Sector records. [More information about Sector here](https://sector.mitre.org/).

            The following key/values are accepted in the body of the request:

            * `version` (required): the version of Sector you want to download in the format `N_N`, e.g. `4_16` for `4.16`. You can see all versions installed and available to download on the version endpoints.
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them. This includes all objects (use ignore SRO/SMO for more granular options). This is a stix2arango setting.
            * `ignore_embedded_relationships_sro` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). Default is `false`. This is a stix2arango setting.
            * `ignore_embedded_relationships_smo` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). Default is `false`. This is a stix2arango setting.
            
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [dogesec](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    list_objects=extend_schema(
        summary="Search and filter Sector objects",
        description=textwrap.dedent(
            """
            Search and filter Sector objects.
            """
        ),
        filters=True,
        responses={
            200: serializers.StixObjectsSerializer(many=True),
            400: DEFAULT_400_ERROR,
        },
    ),
    retrieve_objects=extend_schema(
        summary="Get a Sector object",
        description=textwrap.dedent(
            """
            Get an Sector object by its STIX ID `identity--e6b7b194-b244-5b65-907a-271a89850bb1`.

            If you do not know the ID of the object you can use the GET Sector Objects endpoint to find it.
            """
        ),
        filters=False,
        responses={
            200: serializers.StixObjectsSerializer(many=True),
            400: DEFAULT_400_ERROR,
        },
    ),
    object_versions=extend_schema(
        summary="See all versions of the Sector object",
        description=textwrap.dedent(
            """
            This endpoint will show the STIX versions of the object (`modified` property) and what Sector versions it appears in.

            The data returned is useful to see when and object has changed.
            """
        ),
    ),
    retrieve_object_relationships=extend_schema(
        summary="Get the Relationships linked to Sector Object",
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the Sector object is found as a `source_ref` or a `target_ref`.

            """
        ),
        responses={
            200: ArangoDBHelper.get_paginated_response_schema(
                "relationships", "relationship"
            ),
            400: DEFAULT_400_ERROR,
        },
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters(),
    ),
    bundle=extend_schema(
        summary="Get all objects linked to the Sector Object",
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX objects referenced in `relationship` objects where the source object is found as a `source_ref` or `target_ref`.

            It will also return the `relationship` objects too, allowing you to easily import the entire network graph of objects into other tools.
            """
        ),
        responses={
            200: ArangoDBHelper.get_paginated_response_schema(),
            400: DEFAULT_400_ERROR,
            404: DEFAULT_404_ERROR,
        },
        parameters=BUNDLE_PARAMS,
    ),
    truncate=extend_schema(
        summary=f"Wipe the collections holding Sector objects",
        description=textwrap.dedent(
            f"""
            Wipe the ArangoDB Collections `sector_vertex_collection` and `sector_edge_collection` holding Sector objects.

            **WARNING**: This will delete all objects in these collections, which will mean all Sector versions stored will be removed.
            """
        ),
    ),
)
class SectorView(TruncateView, viewsets.ViewSet):
    openapi_tags = ["Sector"]
    collection_to_truncate = "sector"
    lookup_url_kwarg = "sector_id"
    bucket_name = "sector"
    openapi_path_params = [
        OpenApiParameter(
            "stix_id",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="The STIX ID (e.g. `identity--e6b7b194-b244-5b65-907a-271a89850bb1`, `identity--1a702d8e-3b3e-510f-b572-0c4e9eac4dff`)",
        ),
        OpenApiParameter(
            "sector_id",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="The Sector ID, e.g `engineering-consulting`, `maritime-transport` OR the STIX ID `identity--e6b7b194-b244-5b65-907a-271a89850bb1`.",
        ),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(
            help_text="Filter the results using the STIX ID of an object. e.g. `identity--e6b7b194-b244-5b65-907a-271a89850bb1`, `identity--1a702d8e-3b3e-510f-b572-0c4e9eac4dff`."
        )
        text = CharFilter(
            help_text="Filter the results by the `name` and `description` property of the object. Search is a wildcard, so `engine` will return all descriptions that contain the string `engine`."
        )
        name = CharFilter(
            help_text="Filter results by `name`."
        )
        alias = CharFilter(help_text='Filter the results by the `x_opencti_aliases` property of the object. Search is a wildcard, so `city` will return all objects with `x_opencti_aliases` that contains the string `city`, e.g `Electricity`.')
        sector_version = CharFilter(
            help_text="By default only the latest Sector version objects will be returned. You can enter a specific Sector version here. e.g. `4.13`. You can get a full list of versions on the GET Sector versions endpoint."
        )
        SORT_FIELDS = SECTORS_SORT_FIELDS
        sort = ChoiceFilter(
            choices=[(f, f) for f in SORT_FIELDS],
            help_text="sort by object property/field",
        )

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.SECTOR_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    @decorators.action(methods=["GET"], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper("sector_vertex_collection", request).get_sector_objects()

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "sector_version",
                description="By default only the latest Sector version objects will be returned. You can enter a specific Sector version here. e.g. `4.13`. You can get a full list of versions on the GET Sector versions endpoint.",
            )
        ],
    )
    @decorators.action(
        methods=["GET"], url_path="objects/<str:sector_id>", detail=False
    )
    def retrieve_objects(self, request, *args, sector_id=None, **kwargs):
        return ArangoDBHelper(
            "sector_vertex_collection", request
        ).get_object_by_external_id(
            sector_id, self.lookup_url_kwarg.replace("_id", "_version")
        )

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "sector_version",
                description="By default only the latest Sector version objects will be returned. You can enter a specific Sector version here. e.g. `4.13`. You can get a full list of versions on the GET Sector versions endpoint.",
            )
        ],
    )
    @decorators.action(
        methods=["GET"], url_path="objects/<str:sector_id>/relationships", detail=False
    )
    def retrieve_object_relationships(self, request, *args, sector_id=None, **kwargs):
        return ArangoDBHelper(
            "sector_vertex_collection", request
        ).get_object_by_external_id(
            sector_id,
            self.lookup_url_kwarg.replace("_id", "_version"),
            relationship_mode=True,
        )

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "sector_version",
                description="By default only the latest Sector version objects will be returned. You can enter a specific Sector version here. e.g. `4.13`. You can get a full list of versions on the GET Sector versions endpoint.",
            )
        ],
    )
    @decorators.action(
        methods=["GET"], url_path="objects/<str:sector_id>/bundle", detail=False
    )
    def bundle(self, request, *args, sector_id=None, **kwargs):
        return ArangoDBHelper(
            "sector_vertex_collection", request
        ).get_object_by_external_id(
            sector_id, self.lookup_url_kwarg.replace("_id", "_version"), bundle=True
        )

    @extend_schema(
        summary="See installed Sector versions",
        description=textwrap.dedent(
            """
            It is possible to install multiple versions of Sector
            """
        ),
    )
    @decorators.action(
        detail=False,
        methods=["GET"],
        serializer_class=serializers.MitreVersionsSerializer,
        url_path="versions/installed",
    )
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper("sector_vertex_collection", request).get_mitre_versions()

    @extend_schema(filters=False)
    @decorators.action(
        methods=["GET"],
        url_path="objects/<str:sector_id>/versions",
        detail=False,
        serializer_class=serializers.MitreObjectVersions(many=True),
        pagination_class=None,
    )
    def object_versions(self, request, *args, sector_id=None, **kwargs):
        return ArangoDBHelper(
            f"sector_vertex_collection", request
        ).get_mitre_modified_versions(sector_id, source_name="sector2stix")
