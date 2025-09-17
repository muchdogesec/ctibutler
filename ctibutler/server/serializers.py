from .models import Job
from rest_framework import serializers, validators


ACP_MODES = {
    "capec-attack": "Relate CAPEC objects to ATT&CK objects",
    "cwe-capec": "Relate CWE objects to CAPEC objects",
}

class StixObjectsSerializer(serializers.Serializer):
    type = serializers.CharField()
    id = serializers.CharField()

class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = '__all__'

class MitreTaskSerializer(serializers.Serializer):
    version = serializers.CharField(help_text="version passed to the script", allow_null=False)
    ignore_embedded_relationships = serializers.BooleanField(default=False)
    ignore_embedded_relationships_sro = serializers.BooleanField(default=False)
    ignore_embedded_relationships_smo = serializers.BooleanField(default=False)

class MitreVersionsSerializer(serializers.Serializer):
    latest = serializers.CharField(allow_null=True)
    versions = serializers.ListField(child=serializers.CharField())

class StixVersionsSerializer(serializers.Serializer):
    latest = serializers.DateTimeField(allow_null=True)
    versions = serializers.ListField(child=serializers.DateTimeField())

class MitreObjectVersions(serializers.Serializer):
    modified = serializers.DateTimeField(allow_null=True)
    versions = serializers.ListField(child=serializers.CharField())


class ACPSerializer(serializers.Serializer):
    ignore_embedded_relationships = serializers.BooleanField(default=False)
    modified_min = serializers.DateTimeField(required=False)
    created_min = serializers.DateTimeField(required=False)

class ACPSerializerWithMode(ACPSerializer):
    mode = serializers.ChoiceField(choices=list(ACP_MODES.items()))


class TIEResponseSerializer(serializers.Serializer):
    scores = serializers.DictField()
    objects = serializers.ListField(child=StixObjectsSerializer())


from dogesec_commons.utils.serializers import JSONSchemaSerializer


class AttackNavigatorSerializer(JSONSchemaSerializer):
    json_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "MITRE ATT&CK Navigator Layer v4.5",
        "type": "object",
        "required": ["versions", "name", "domain", "techniques"],
        "properties": {
            "versions": {
                "type": "object",
                "description": "Version information for ATT&CK Navigator and Layer.",
                "properties": {
                    "layer": {"type": "string"},
                    "attack": {"type": "string"},
                    "navigator": {"type": "string"},
                },
            },
            "name": {"type": "string"},
            "domain": {
                "type": "string",
                "enum": ["enterprise-attack", "mobile-attack", "ics-attack"],
            },
            "description": {"type": "string"},
            "gradient": {
                "type": "object",
                "required": ["colors", "minValue", "maxValue"],
                "properties": {
                    "colors": {
                        "type": "array",
                        "items": {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"},
                    },
                    "minValue": {"type": "number"},
                    "maxValue": {"type": "number"},
                },
            },
            "legendItems": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string"},
                        "color": {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"},
                        "value": {"type": "number"},
                    },
                },
            },
            "showTacticsRowBackground": {"type": "boolean"},
            "techniques": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["techniqueID"],
                    "properties": {
                        "showSubtechniques": {"type": "boolean"},
                        "techniqueID": {"type": "string"},
                        "score": {"type": ["number", "null"]},
                        "color": {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"},
                        "comment": {"type": "string"},
                        "enabled": {"type": "boolean"},
                        "links": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "href": {"type": "string", "format": "uri"},
                                    "text": {"type": "string"},
                                },
                                "required": ["href", "text"],
                            },
                        },
                    },
                    "additionalProperties": False,
                },
            },
            "tacticUseIds": {"type": "array", "items": {"type": "string"}},
            "filters": {
                "type": "object",
                "properties": {
                    "includeSubtechniques": {"type": "boolean"},
                    "showOnlyVisibleTechniques": {"type": "boolean"},
                },
            },
        },
        "additionalProperties": True,
    }
