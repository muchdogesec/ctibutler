import contextlib
from pathlib import Path
import re
import typing
from arango import ArangoClient
from django.conf import settings
from .utils import Pagination, Response
from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from rest_framework.validators import ValidationError
from ..server import utils
if typing.TYPE_CHECKING:
    from .. import settings

import textwrap

SDO_TYPES = set(
    [
        "report",
        "note",
        "indicator",
        "attack-pattern",
        "weakness",
        "campaign",
        "course-of-action",
        "infrastructure",
        "intrusion-set",
        "malware",
        "threat-actor",
        "tool",
        "identity",
        "location",
    ]
)
SCO_TYPES = set(
    [
        "ipv4-addr",
        "network-traffic",
        "ipv6-addr",
        "domain-name",
        "url",
        "file",
        "directory",
        "email-addr",
        "mac-addr",
        "windows-registry-key",
        "autonomous-system",
        "user-agent",
        "cryptocurrency-wallet",
        "cryptocurrency-transaction",
        "bank-card",
        "bank-account",
        "phone-number",
    ]
)
TLP_TYPES = set([
    "marking-definition"
])
ATTACK_TYPES = set([
    "attack-pattern",
    "campaign",
    "course-of-action",
    "identity",
    "intrusion-set",
    "malware",
    "marking-definition",
    "tool",
    "x-mitre-data-component",
    "x-mitre-data-source",
    "x-mitre-matrix",
    "x-mitre-tactic"
]
)
LOCATION_TYPES = set([
    'location'
])
CWE_TYPES = set([
    "weakness",
    # "grouping",
    # "identity",
    # "marking-definition",
    # "extension-definition"
]
)

DISARM_TYPES = set([
  "attack-pattern",
  "identity",
  "marking-definition",
  "x-mitre-matrix",
  "x-mitre-tactic"
])

ATLAS_TYPES = set([
  "attack-pattern",
  "course-of-action",
#   "identity",
#   "marking-definition",
  "x-mitre-collection",
  "x-mitre-matrix",
  "x-mitre-tactic"
])

SOFTWARE_TYPES = set([
    "software",
    "identity",
    "marking-definition"
]
)
CAPEC_TYPES = set([
  "attack-pattern",
  "course-of-action",
  "identity",
  "marking-definition"
]
)

LOCATION_SUBTYPES = set(
[
  "intermediate-region",
  "sub-region",
  "region",
  "country"
]
)

CVE_SORT_FIELDS = [
    "modified_descending",
    "modified_ascending",
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
    "epss_score_ascending",
    "epss_score_descending",
    "cvss_base_score_ascending",
    "cvss_base_score_descending",
]
OBJECT_TYPES = SDO_TYPES.union(SCO_TYPES).union(["relationship"])


def positive_int(integer_string, cutoff=None, default=1):
    """
    Cast a string to a strictly positive integer.
    """
    with contextlib.suppress(ValueError, TypeError):
        ret = int(integer_string)
        if ret <= 0:
            return default
        if cutoff:
            return min(ret, cutoff)
        return ret
    return default

class ArangoDBHelper:
    max_page_size = settings.MAXIMUM_PAGE_SIZE
    page_size = settings.DEFAULT_PAGE_SIZE

    def get_sort_stmt(self, sort_options: list[str], customs={}):
        finder = re.compile(r"(.+)_((a|de)sc)ending")
        sort_field = self.query.get('sort', sort_options[0])
        if sort_field not in sort_options:
            return ""
        if m := finder.match(sort_field):
            field = m.group(1)
            direction = m.group(2).upper()
            if cfield := customs.get(field):
                return f"SORT {cfield} {direction}"
            return f"SORT doc.{field} {direction}"

    def query_as_array(self, key):
        query = self.query.get(key)
        if not query:
            return []
        return query.split(',')
    def query_as_bool(self, key, default=True):
        query_str = self.query.get(key)
        if not query_str:
            return default
        return query_str.lower() == 'true'
    
    @classmethod
    def get_page_params(cls, request):
        kwargs = request.GET.copy()
        page_number = positive_int(kwargs.get('page'))
        page_limit = positive_int(kwargs.get('page_size'), cutoff=ArangoDBHelper.max_page_size, default=ArangoDBHelper.page_size)
        return page_number, page_limit

    @classmethod
    def get_paginated_response(cls, container,  data, page_number, page_size=page_size, full_count=0):
        return Response(
            {
                "page_size": page_size or cls.page_size,
                "page_number": page_number,
                "page_results_count": len(data),
                "total_results_count": full_count,
                container: data,
            }
        )
    @classmethod
    def get_paginated_response_schema(cls, container='objects', stix_type='identity'):
        if stix_type == 'string':
            container_schema = {'type':'string'}
        else:
            container_schema = {
                            "type": "object",
                            "properties": {
                                "type":{
                                    "example": stix_type,
                                },
                                "id": {
                                    "example": f"{stix_type}--a86627d4-285b-5358-b332-4e33f3ec1075",
                                },
                            },
                            "additionalProperties": True,
                        }
        return {
                "type": "object",
                "required": ["page_results_count", container],
                "properties": {
                    "page_size": {
                        "type": "integer",
                        "example": cls.max_page_size,
                    },
                    "page_number": {
                        "type": "integer",
                        "example": 3,
                    },
                    "page_results_count": {
                        "type": "integer",
                        "example": cls.page_size,
                    },
                    "total_results_count": {
                        "type": "integer",
                        "example": cls.page_size * cls.max_page_size,
                    },
                    container: {'type': 'array', 'items': container_schema}
                }
        }

    @classmethod
    def get_relationship_schema_operation_parameters(cls):
        return cls.get_schema_operation_parameters() + [
            OpenApiParameter(
                "include_embedded_refs",
                description=textwrap.dedent(
                    """
                    If `ignore_embedded_relationships` is set to `false` in the POST request to download data, stix2arango will create SROS for embedded relationships (e.g. from `created_by_refs`). You can choose to show them (`true`) or hide them (`false`) using this parameter. Default value if not passed is `true`.
                    """
                ),
                type=OpenApiTypes.BOOL
            ),
            OpenApiParameter(
                "relationship_direction",
                enum=["source_ref", "target_ref"],
                description=textwrap.dedent(
                    """
                    Filters the results to only include SROs which have this object in the specified SRO property (e.g. setting `source_ref` will only return SROs where the object is shown in the `source_ref` property). Default is both.
                    """
                ),
            ),
            OpenApiParameter(
                "relationship_type",
                description="filter by the `relationship_type` of the STIX SROs returned."
            )
        ]
    @classmethod
    def get_schema_operation_parameters(self):
        parameters = [
            OpenApiParameter(
                Pagination.page_query_param,
                type=int,
                description=Pagination.page_query_description,
            ),
            OpenApiParameter(
                Pagination.page_size_query_param,
                type=int,
                description=Pagination.page_size_query_description,
            ),
        ]
        return parameters
    client = ArangoClient(
        hosts=settings.ARANGODB_HOST_URL
    )
    DB_NAME = f"{settings.ARANGODB_DATABASE}_database"
    def __init__(self, collection, request, container='objects') -> None:
        self.collection = collection
        self.db = self.client.db(
            self.DB_NAME,
            username=settings.ARANGODB_USERNAME,
            password=settings.ARANGODB_PASSWORD,
        )
        self.container = container
        self.page, self.count = self.get_page_params(request)
        self.request = request
        self.query = request.query_params.dict()
    def execute_query(self, query, bind_vars={}, paginate=True, relationship_mode=False, container=None):
        if relationship_mode:
            return self.get_relationships(query, bind_vars)
        if paginate:
            bind_vars['offset'], bind_vars['count'] = self.get_offset_and_count(self.count, self.page)
        cursor = self.db.aql.execute(query, bind_vars=bind_vars, count=True, full_count=True)
        if paginate:
            return self.get_paginated_response(container or self.container, cursor, self.page, self.page_size, cursor.statistics()["fullCount"])
        return list(cursor)
   
    def get_offset_and_count(self, count, page) -> tuple[int, int]:
        page = page or 1
        if page >= 2**32:
            raise ValidationError(f"invalid page `{page}`")
        offset = (page-1)*count
        return offset, count

    def get_attack_objects(self, matrix):
        filters = []
        types = ATTACK_TYPES
        if new_types := self.query_as_array('type'):
            types = types.intersection(new_types)
        bind_vars = {
                "@collection": f'mitre_attack_{matrix}_vertex_collection',
                "types": list(types),
        }

        if q := self.query.get(f'attack_version'):
            bind_vars['mitre_version'] = "version="+q.replace('.', '_').strip('v')
            filters.append('FILTER doc._stix2arango_note == @mitre_version')
        else:
            filters.append('FILTER doc._is_latest')

        if value := self.query_as_array('id'):
            bind_vars['ids'] = value
            filters.append(
                "FILTER doc.id in @ids"
            )

        bind_vars['include_deprecated'] = self.query_as_bool('include_deprecated', False)
        bind_vars['include_revoked'] = self.query_as_bool('include_revoked', False)

        if value := self.query_as_array('attack_id'):
            bind_vars['attack_ids'] = [v.lower() for v in value]
            filters.append(
                "FILTER LOWER(doc.external_references[0].external_id) in @attack_ids"
            )
        if q := self.query.get('name'):
            bind_vars['name'] = q.lower()
            filters.append('FILTER CONTAINS(LOWER(doc.name), @name)')

        if q := self.query.get('alias'):
            bind_vars['alias'] = q.lower()
            filters.append('FILTER APPEND(doc.aliases, doc.x_mitre_aliases)[? ANY FILTER CONTAINS(LOWER(CURRENT), @alias)]')

        if q := self.query.get('description'):
            bind_vars['description'] = q.lower()
            filters.append('FILTER CONTAINS(LOWER(doc.description), @description)')

        query = """
            FOR doc in @@collection
            FILTER CONTAINS(@types, doc.type) AND (@include_revoked OR NOT doc.revoked) AND (@include_deprecated OR NOT doc.x_mitre_deprecated)
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """.replace('@filters', '\n'.join(filters))
        return self.execute_query(query, bind_vars=bind_vars)


    def get_object_by_external_id(self, ext_id: str, relationship_mode=False, revokable=False):
        bind_vars={'@collection': self.collection, 'ext_id': ext_id.lower()}
        filters = ['FILTER doc._is_latest']
        for version_param in ['attack_version', 'cwe_version', 'capec_version']:
            if q := self.query.get(version_param):
                bind_vars['mitre_version'] = "version="+q.replace('.', '_').strip('v')
                filters[0] = 'FILTER doc._stix2arango_note == @mitre_version'
                break
        
        if revokable:
            bind_vars['include_deprecated'] = self.query_as_bool('include_deprecated', False)
            bind_vars['include_revoked'] = self.query_as_bool('include_revoked', False)
            filters.append('FILTER (@include_revoked OR NOT doc.revoked) AND (@include_deprecated OR NOT doc.x_mitre_deprecated)')
        
        return self.execute_query('''
            FOR doc in @@collection
            FILTER LOWER(doc.external_references[0].external_id) == @ext_id
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
            '''.replace('@filters', '\n'.join(filters)), bind_vars=bind_vars, relationship_mode=relationship_mode)

    def get_mitre_versions(self, stix_id=None):
        query = """
        FOR doc IN @@collection
        FILTER STARTS_WITH(doc._stix2arango_note, "version=")
        RETURN DISTINCT doc._stix2arango_note
        """
        bind_vars = {'@collection': self.collection}
        versions = self.execute_query(query, bind_vars=bind_vars, paginate=False)
        versions = self.clean_and_sort_versions(versions)
        return Response(dict(latest=versions[0] if versions else None, versions=versions))

    def get_mitre_modified_versions(self, external_id: str=None, source_name='mitre-attack'):
        query = """
        FOR doc IN @@collection
        FILTER doc.external_references[? ANY FILTER LOWER(CURRENT.external_id) == @matcher.external_id AND @matcher.source_name == CURRENT.source_name] AND STARTS_WITH(doc._stix2arango_note, "version=")
        FILTER (@include_revoked OR NOT doc.revoked) AND (@include_deprecated OR NOT doc.x_mitre_deprecated) // for MITRE ATT&CK, check if revoked
        COLLECT modified = doc.modified INTO group
        SORT modified DESC
        RETURN {modified, versions: UNIQUE(group[*].doc._stix2arango_note)}
        """
        bind_vars = {
            '@collection': self.collection, 'matcher': dict(external_id=external_id.lower(), source_name=source_name),
            # include_deprecated / include_revoked
            'include_revoked': self.query_as_bool('include_revoked', False),
            'include_deprecated': self.query_as_bool('include_deprecated', False),
            }
        versions = self.execute_query(query, bind_vars=bind_vars, paginate=False)
        for mod in versions:
            mod['versions'] = self.clean_and_sort_versions(mod['versions'])
        return Response(versions)
    
    def get_modified_versions(self, stix_id=None):
        query = """
        FOR doc IN @@collection
        FILTER doc.id == @stix_id AND STARTS_WITH(doc._stix2arango_note, "version=")
        COLLECT modified = doc.modified INTO group
        SORT modified DESC
        RETURN {modified, versions: UNIQUE(group[*].doc._stix2arango_note)}
        """
        bind_vars = {'@collection': self.collection, 'stix_id': stix_id}
        versions = self.execute_query(query, bind_vars=bind_vars, paginate=False)
        for mod in versions:
            mod['versions'] = self.clean_and_sort_versions(mod['versions'])
        return Response(versions)
    
    def clean_and_sort_versions(self, versions):
        versions = sorted([
            v.split("=")[1].replace('_', ".")
            for v in versions
        ], key=utils.split_mitre_version, reverse=True)
        return [f"{v}" for v in versions]

    def get_weakness_or_capec_objects(self, cwe=True, types=CWE_TYPES, lookup_kwarg='cwe_id', more_binds={}, more_filters=[]):
        version_param = lookup_kwarg.replace('_id', '_version')
        filters = []
        if new_types := self.query_as_array('type'):
            types = types.intersection(new_types)

        bind_vars = {
                "@collection": self.collection,
                "types": list(types),
                **more_binds
        }
        if q := self.query.get(version_param):
            bind_vars['mitre_version'] = "version="+q.replace('.', '_').strip('v')
            filters.append('FILTER doc._stix2arango_note == @mitre_version')
        else:
            filters.append('FILTER doc._is_latest')

        if value := self.query_as_array('id'):
            bind_vars['ids'] = value
            filters.append(
                "FILTER doc.id in @ids"
            )

        if value := self.query_as_array(lookup_kwarg):
            bind_vars['ext_ids'] = [v.lower() for v in value]
            filters.append(
                "FILTER LOWER(doc.external_references[0].external_id) in @ext_ids"
            )
        if q := self.query.get('name'):
            bind_vars['name'] = q.lower()
            filters.append('FILTER CONTAINS(LOWER(doc.name), @name)')

        if q := self.query.get('description'):
            bind_vars['description'] = q.lower()
            filters.append('FILTER CONTAINS(LOWER(doc.description), @description)')

        query = """
            FOR doc in @@collection
            FILTER CONTAINS(@types, doc.type)
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """.replace('@filters', '\n'.join(filters+more_filters))
        return self.execute_query(query, bind_vars=bind_vars)

    def get_object(self, stix_id, relationship_mode=False, version_param=None):
        bind_vars={'@collection': self.collection, 'stix_id': stix_id}
        filters = ['FILTER doc._is_latest']
        if version_param and self.query.get(version_param):
            bind_vars['mitre_version'] = "version="+self.query.get(version_param).replace('.', '_').strip('v')
            filters[0] = 'FILTER doc._stix2arango_note == @mitre_version'

        return self.execute_query('''
            FOR doc in @@collection
            FILTER doc.id == @stix_id
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
            '''.replace('@filters', '\n'.join(filters)), bind_vars=bind_vars, relationship_mode=relationship_mode)


    def get_relationships(self, docs_query, binds):
        regex = r"KEEP\((\w+),\s*\w+\(.*?\)\)"
        binds['@view'] = settings.VIEW_NAME
        other_filters = []

        if term := self.query.get('relationship_type'):
            binds['rel_relationship_type'] = term.lower()
            other_filters.append("FILTER CONTAINS(LOWER(d.relationship_type), @rel_relationship_type) OR CONTAINS(LOWER(d._arango_cti_processor_note), @rel_relationship_type)")

        if term := self.query_as_array('source_ref'):
            binds['rel_source_ref'] = term
            other_filters.append('FILTER d.source_ref IN @rel_source_ref')

        if terms := self.query_as_array('source_ref_type'):
            binds['rel_source_ref_type'] = terms
            other_filters.append('FILTER SPLIT(d.source_ref, "--")[0] IN @rel_source_ref_type')

        if term := self.query_as_array('target_ref'):
            binds['rel_target_ref'] = term
            other_filters.append('FILTER d.target_ref IN @rel_target_ref')

        if terms := self.query_as_array('target_ref_type'):
            binds['rel_target_ref_type'] = terms
            other_filters.append('FILTER SPLIT(d.target_ref, "--")[0] IN @rel_target_ref_type')

        match self.query.get('relationship_direction'):
            case 'source_ref':
                direction_query = 'd._from IN matched_ids'
            case 'target_ref':
                direction_query = 'd._to IN matched_ids'
            case _:
                direction_query = 'd._from IN matched_ids OR d._to IN matched_ids'

        if self.query_as_bool('include_embedded_refs', True):
            embedded_refs_query = ''
        else:
            embedded_refs_query = 'AND d._is_ref != TRUE'

        new_query = """
        LET matched_ids = (@docs_query)[*]._id
        FOR d IN @@view
        SEARCH d.type == 'relationship' AND (@direction_query) @include_embedded_refs
        @other_filters
        LIMIT @offset, @count
        RETURN KEEP(d, KEYS(d, TRUE))
        """.replace('@docs_query', re.sub(regex, lambda x: x.group(1), docs_query.replace('LIMIT @offset, @count', ''))) \
            .replace('@other_filters', "\n".join(other_filters)) \
            .replace('@direction_query', direction_query) \
            .replace('@include_embedded_refs', embedded_refs_query)

        return self.execute_query(new_query, bind_vars=binds, container='relationships')
