from typing import List
from drf_spectacular.openapi import AutoSchema
from dogesec_commons.utils.serializers import CommonErrorSerializer as ErrorSerializer
from drf_spectacular.utils import OpenApiResponse, OpenApiExample
import uritemplate
from dogesec_commons.utils.autoschema import CustomAutoSchema

class CtibutlerAutoSchema(CustomAutoSchema):
    pass

DEFAULT_400_ERROR = OpenApiResponse(
    ErrorSerializer,
    "The server did not understand the request",
    [
        OpenApiExample(
            "http400",
            {"message": " The server did not understand the request", "code": 400},
        )
    ],
)


DEFAULT_404_ERROR = OpenApiResponse(
    ErrorSerializer,
    "Resource not found",
    [
        OpenApiExample(
            "http404",
            {
                "message": "The server cannot find the resource you requested",
                "code": 404,
            },
        )
    ],
)
