"""Job View for managing and querying job status."""
import textwrap
from rest_framework import viewsets
from rest_framework.response import Response

from django_filters.rest_framework import FilterSet, Filter, DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from ctibutler.server.autoschema import DEFAULT_400_ERROR, DEFAULT_404_ERROR
from ctibutler.server.utils import Pagination, Ordering
from ctibutler.server import models
from ctibutler.server import serializers

from .commons import ChoiceCSVFilter


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
            # Import here to avoid circular import
            from .attack_view import AttackView
            
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

        def filter_type(self, qs, field_name, value: list[str]):
            from django.db.models import Q
            query = Q()
            for t in value:
                type, _, mode = t.partition('--')
                q = Q(type=type)
                if mode:
                    q &= Q(parameters__mode=mode)
                query |= q
            return qs.filter(query)
