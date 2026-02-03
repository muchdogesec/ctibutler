"""ACP (Arango CTI Processor) View for managing CTI processing jobs."""
import textwrap
from rest_framework import viewsets, status
from rest_framework.response import Response

from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from ctibutler.server.autoschema import DEFAULT_400_ERROR
from ctibutler.worker.tasks import new_task
from ctibutler.server import models
from ctibutler.server import serializers


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
            * `version` (optional): controls the source version of objects used. This only really applies for `d3fend-attack` mode (although can be used with all modes) b/c the way relationship generation happens internally (that is all data is already held in the knowledgebase). So if you are using D3FEND `1.3.0` you should pass that value here, to ensure relationships to other versions are not created. This will not affect the `_is_latest` behaviour, b/c this always considers the highest modified time, regardless of version passed.
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
