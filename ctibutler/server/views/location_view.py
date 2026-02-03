import textwrap
from rest_framework import viewsets, status, decorators
from django_filters.rest_framework import FilterSet, DjangoFilterBackend, ChoiceFilter, CharFilter, BaseInFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from ctibutler.server.arango_helpers import ArangoDBHelper, LOCATION_TYPES, LOCATION_SUBTYPES
from ctibutler.server.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR
from ctibutler.server.utils import Pagination, Response
from ctibutler.worker.tasks import new_task
from ctibutler.server import models
from ctibutler.server import serializers
from django_filters import BaseCSVFilter

from .commons import TruncateView, BUNDLE_PARAMS, REVOKED_AND_DEPRECATED_PARAMS


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
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR, 404: DEFAULT_404_ERROR},
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
        SORT_FIELDS = ["modified_descending", "modified_ascending", "created_ascending", "created_descending", "name_ascending", "name_descending",'location_id_ascending', 'location_id_descending', 'location_type_ascending', 'location_type_descending']
        sort = ChoiceFilter(choices=[(f,f) for f in SORT_FIELDS], help_text="sort by object property/field")

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
                OpenApiParameter('location_version', description="By default only the latest Location version objects will be returned. You can enter a specific Location version here. e.g. `1.0`. You can get a full list of versions on the GET Location versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:location_id>", detail=False)
    def retrieve_objects(self, request, *args, location_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(location_id, self.lookup_url_kwarg.replace('_id', '_version'))
    
      
    @extend_schema(
            parameters=[
                OpenApiParameter('location_version', description="By default only the latest Location version objects will be returned. You can enter a specific Location version here. e.g. `1.0`. You can get a full list of versions on the GET Location versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:location_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, location_id=None, **kwargs):
        return ArangoDBHelper(self.arango_collection, request).get_object_by_external_id(location_id, self.lookup_url_kwarg.replace('_id', '_version'), relationship_mode=True)
    
    @extend_schema(
            parameters=[
                OpenApiParameter('location_version', description="By default only the latest Location version objects will be returned. You can enter a specific Location version here. e.g. `1.0`. You can get a full list of versions on the GET Location versions endpoint.")
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
