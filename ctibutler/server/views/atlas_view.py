"""ATLAS View for handling MITRE ATLAS objects."""
import textwrap
from rest_framework import viewsets, status, decorators
from rest_framework.response import Response

from django_filters.rest_framework import FilterSet, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from ctibutler.server.arango_helpers import ATLAS_FORMS, ATLAS_TYPES, CTI_SORT_FIELDS, ArangoDBHelper
from ctibutler.server.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR
from ctibutler.server.utils import Pagination, Response
from ctibutler.worker.tasks import new_task
from ctibutler.server import models
from ctibutler.server import serializers

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
        responses={200: ArangoDBHelper.get_paginated_response_schema(), 400: DEFAULT_400_ERROR, 404: DEFAULT_404_ERROR},
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
        text = CharFilter(help_text='Filter the results by the `name` and `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter results by `name`. Is wildcard so `evi` will match `revil`, `evil`, etc.')
        types = ChoiceCSVFilter(choices=[(f,f) for f in ATLAS_TYPES], help_text='Filter the results by STIX Object type.')
        atlas_version = CharFilter(help_text="By default only the latest ATLAS version objects will be returned. You can enter a specific ATLAS version here. e.g. `4.9.0`. You can get a full list of versions on the GET ATLAS versions endpoint.")
        atlas_type = ChoiceCSVFilter(choices=[(f,f) for f in ATLAS_FORMS], help_text='Filter the results by ATLAS Object type.')
        SORT_FIELDS = CTI_SORT_FIELDS+['atlas_id_ascending', 'atlas_id_descending']
        sort = ChoiceFilter(choices=[(f,f) for f in SORT_FIELDS], help_text="sort by object property/field")

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
                OpenApiParameter('atlas_version', description="By default only the latest ATLAS version objects will be returned. You can enter a specific ATLAS version here. e.g. `4.9.0`. You can get a full list of versions on the GET ATLAS versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>", detail=False)
    def retrieve_objects(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_object_by_external_id(atlas_id, self.lookup_url_kwarg.replace('_id', '_version'))    
    @extend_schema(
            parameters=[
                OpenApiParameter('atlas_version', description="By default only the latest ATLAS version objects will be returned. You can enter a specific ATLAS version here. e.g. `4.9.0`. You can get a full list of versions on the GET ATLAS versions endpoint.")
            ],
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:atlas_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, atlas_id=None, **kwargs):
        return ArangoDBHelper('mitre_atlas_vertex_collection', request).get_object_by_external_id(atlas_id, self.lookup_url_kwarg.replace('_id', '_version'), relationship_mode=True)
        
    @extend_schema(
            parameters=[
                OpenApiParameter('atlas_version', description="By default only the latest ATLAS version objects will be returned. You can enter a specific ATLAS version here. e.g. `4.9.0`. You can get a full list of versions on the GET ATLAS versions endpoint.")
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
