"""Utility views for server health and API schema."""
import textwrap
from rest_framework import status, decorators
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from drf_spectacular.views import SpectacularAPIView


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
    """Simple health check endpoint."""
    return Response(status=status.HTTP_204_NO_CONTENT)


class SchemaViewCached(SpectacularAPIView):
    """Cached version of the API schema view."""
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
