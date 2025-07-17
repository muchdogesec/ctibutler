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
    for v in re.split(r'_|-|\.', version.strip('v')):
        try:
            v = int(v)
        except:
            pass
        finally:
            version_parts.append(v)
    print(repr(version_parts))
    return tuple(version_parts)