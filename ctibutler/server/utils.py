import re
from django.conf import settings
from rest_framework import pagination, response, serializers
from rest_framework.filters import OrderingFilter, BaseFilterBackend
from django.utils.encoding import force_str
from django.db.models import Q
from datetime import datetime
from rest_framework import response
from rest_framework.views import exception_handler
from dogesec_commons.utils import Pagination, Ordering


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    resp = exception_handler(exc, context)

    # Now add the HTTP status code to the response.
    if resp is not None:
        resp.data = dict(code=resp.status_code, details=resp.data)

    return resp

class MinMaxDateFilter(BaseFilterBackend):
    min_val = datetime.min
    max_value = datetime.max
    def get_fields(self, view):
        out = {}
        fields = getattr(view, 'minmax_date_fields', [])
        if not isinstance(fields, list):
            return out
        for field in fields:
            out[f"{field}_max"] = field
            out[f"{field}_min"] = field
        return out

    def filter_queryset(self, request, queryset, view):
        valid_fields = self.get_fields(view)
        valid_params = [(k, v) for k, v in request.query_params.items() if k in valid_fields]
        queries =  {}
        for param, value in valid_params:
            field_name = valid_fields[param]
            if param.endswith('_max'):
                queries[f"{field_name}__lte"] = value
            else:
                queries[f"{field_name}__gte"] = value
        return queryset.filter(Q(**queries))

    def get_schema_operation_parameters(self, view):
        parameters = []
        valid_fields = self.get_fields(view)
        for query_name, field_name in valid_fields.items():
            _type = "Maximum"
            if query_name.endswith('min'):
                _type = "Minimum"
            parameter = {
                'name': query_name,
                'required': False,
                'in': 'query',
                'description': f"{_type} value of `{field_name}` to filter by in format `YYYY-MM-DD`.",
                'schema': {
                    'type': 'string', 'format': 'date',
                },
            }
            parameters.append(parameter)
        return parameters


class Response(response.Response):
    DEFAULT_HEADERS = {
        'Access-Control-Allow-Origin': '*',
    }
    CONTENT_TYPE = "application/json"
    def __init__(self, data=None, status=None, template_name=None, headers=None, exception=False, content_type=CONTENT_TYPE):
        headers = headers or {}
        headers.update(self.DEFAULT_HEADERS)
        super().__init__(data, status, template_name, headers, exception, content_type)
    
class ErrorResp(Response):
    def __init__(self, status, title, details=None):
        super().__init__({"message": title, "code": status}, status=status)


def split_mitre_version(version: str):
    version_parts = []
    for v in re.split('_|-|\.', version.strip('v')):
        try:
            v = int(v)
        except:
            pass
        finally:
            version_parts.append(v)
    return tuple(version_parts)