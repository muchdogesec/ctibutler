"""
Common utilities, filters, and parameters used across view classes.
"""
import logging
import textwrap
import requests
from django.conf import settings
from rest_framework import status, decorators, exceptions, parsers
from rest_framework.response import Response

from django_filters.rest_framework import BaseCSVFilter
from django_filters.fields import ChoiceField
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from ctibutler.server.arango_helpers import ALL_SEARCH_TYPES, ArangoDBHelper


class ChoiceCSVFilter(BaseCSVFilter):
    """CSV filter for choice fields."""
    field_class = ChoiceField


REVOKED_AND_DEPRECATED_PARAMS = [
    OpenApiParameter('include_revoked', type=OpenApiTypes.BOOL, description="By default all objects with `revoked` are ignored. Set this to `true` to include them."),
    OpenApiParameter('include_deprecated', type=OpenApiTypes.BOOL, description="By default all objects with `x_mitre_deprecated` are ignored. Set this to `true` to include them."),
]

BUNDLE_PARAMS = ArangoDBHelper.get_schema_operation_parameters() + [
    OpenApiParameter(
        "include_embedded_refs",
        description=textwrap.dedent(
            """
            If `ignore_embedded_relationships` is set to `false` in the POST request to download data, stix2arango will create SROS for embedded relationships (e.g. from `created_by_refs`). You can choose to show them (`true`) or hide them (`false`) using this parameter. Default value if not passed is `true`. If set to `true` then the objects referenced in the embedded refs relationships will not be shown. This is an arango_cti_processor setting.
            """
        ),
        type=OpenApiTypes.BOOL,
    ),
    OpenApiParameter(
        "types",
        description="Only show objects of selected types",
        enum=ALL_SEARCH_TYPES,
        explode=False,
        style="form",
        many=True,
    ),
    OpenApiParameter(
        "include_embedded_sros",
        type=OpenApiTypes.BOOL,
        description="set to `true` to include the embedded relationships linking the objects. Setting to `false` (default) will still return the target object, but wont return the embedded SRO linking them. Set to `true` if your downstream software CANNOT interpret STIX embedded relationships",
    ),
]


class TruncateView:
    """Base view mixin providing truncation and version management functionality."""
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
                collection_.truncate(sync=True)
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
