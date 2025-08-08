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