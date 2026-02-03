import textwrap
from rest_framework import viewsets
from django_filters.rest_framework import FilterSet, DjangoFilterBackend, ChoiceFilter, CharFilter, BooleanFilter
from drf_spectacular.utils import extend_schema, extend_schema_view

from ctibutler.server.arango_helpers import ArangoDBHelper, ALL_SEARCH_TYPES, KNOWLEDGE_BASE_TO_COLLECTION_MAPPING, SEMANTIC_SEARCH_SORT_FIELDS
from ctibutler.server.autoschema import DEFAULT_400_ERROR
from ctibutler.server.utils import Pagination
from ctibutler.server import serializers

from .commons import ChoiceCSVFilter, REVOKED_AND_DEPRECATED_PARAMS


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
        types = ChoiceCSVFilter(choices=[(f,f) for f in ALL_SEARCH_TYPES], help_text='Filter the results by STIX Object type.')
        knowledge_bases = ChoiceCSVFilter(choices=[(f, f) for f in KNOWLEDGE_BASE_TO_COLLECTION_MAPPING], help_text='Filter results by containing knowledgebase you want to search. If not passed will search all knowledgebases in CTI Butler')
        show_knowledgebase = BooleanFilter(help_text="If `true`, will add `knowledgebase_name` property to each returend object. Note, setting to `true` will break the objects in the response from being pure STIX 2.1. Default is `false`")
        sort = ChoiceFilter(choices=[(f, f) for f in SEMANTIC_SEARCH_SORT_FIELDS], help_text="attribute to sort by")
    def list(self, request, *args, **kwargs):
        return ArangoDBHelper("semantic_search_view", request).semantic_search()
