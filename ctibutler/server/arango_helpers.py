from pathlib import Path
import re
import typing
from arango import ArangoClient
from django.conf import settings
from .utils import Pagination, Response
from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.types import OpenApiTypes

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
        page_number = int(kwargs.get('page', 1))
        page_limit  = min(int(kwargs.get('page_size', ArangoDBHelper.page_size)), ArangoDBHelper.max_page_size)
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
                    container: container_schema
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
        offset = (page-1)*count
        return offset, count

    def get_vulnerabilities(self):
        binds = {}
        filters = []

        if q := self.query.get('cvss_base_score_min'):
            binds['cvss_base_score_min'] = float(q)
            filters.append("FILTER VALUES(doc.x_cvss)[? FILTER CURRENT.base_score >= @cvss_base_score_min]")

        if value := self.query_as_array('stix_id'):
            binds['stix_ids'] = value
            filters.append(
                "FILTER doc.id in @stix_ids"
            )

        if q := self.query.get('epss_score_min'):
            binds['epss_score_min'] = float(q)
            filters.append("FILTER doc.x_epss.score >= @epss_score_min")

        if q := self.query.get('epss_percentile_min'):
            binds['epss_percentile_min'] = float(q)
            filters.append("FILTER doc.x_epss.percentile >= @epss_percentile_min")

        for v in ['created', 'modified']:
            mn, mx = f'{v}_min', f'{v}_max'
            if q := self.query.get(mn):
                binds[mn] = q
                filters.append(f"FILTER doc.{v} >= @{mn}")

            if q := self.query.get(mx):
                binds[mx] = q
                filters.append(f"FILTER doc.{v} <= @{mx}")

        if q := self.query_as_array('cpes_vulnerable'):
            binds['cpes_vulnerable'] = q
            filters.append('''
            LET vulnerable_cpes = (FOR d in nvd_cve_edge_collection FILTER d._from == indicator_ref AND d.relationship_type == 'is-vulnerable' AND DOCUMENT(d._to).cpe IN @cpes_vulnerable RETURN TRUE)
            FILTER LENGTH(vulnerable_cpes) > 0
            ''')
        if q := self.query_as_array('cpes_in_pattern'):
            binds['cpes_in_pattern'] = q
            filters.append('''
            LET cpes_in_pattern = (FOR d in nvd_cve_edge_collection FILTER d._from == indicator_ref AND d.relationship_type == 'pattern-contains' AND DOCUMENT(d._to).cpe IN @cpes_in_pattern RETURN TRUE)
            FILTER LENGTH(cpes_in_pattern) > 0
            ''')

        if q := self.query_as_array('cve_id'):
            binds['cve_ids'] = q
            filters.append('FILTER doc.external_references[0].external_id IN @cve_ids')

        if (q := self.query_as_bool('has_kev', None)) != None:
            binds['has_kev'] = q
            filters.append('''
            LET hasKev = LENGTH(FOR d IN nvd_cve_edge_collection FILTER doc._id == d._to AND d.relationship_type == 'sighting-of' RETURN d._from) > 0
            FILTER hasKev == @has_kev
            ''')

        if q := self.query_as_array('weakness_id'):
            binds['weakness_ids'] = q
            filters.append('''
                FILTER LENGTH(FOR d IN nvd_cve_edge_collection FILTER doc._id == d._from AND d.relationship_type == 'exploited-using' AND LAST(SPLIT(d.description, ' ')) IN @weakness_ids LIMIT 1 RETURN TRUE) > 0
                ''')

        query = """
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'vulnerability' AND doc._is_latest
LET indicator_ref = FIRST(FOR d IN nvd_cve_edge_collection FILTER doc._id == d._to RETURN d._from)
@filters
@sort_stmt
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, true))
    """.replace(
            "@filters", "\n".join(filters)
        ).replace(
            "@sort_stmt",
            self.get_sort_stmt(
                CVE_SORT_FIELDS,
                {
                    "epss_score": "doc.x_epss.score",
                    "cvss_base_score": "FIRST(VALUES(doc.x_cvss)).base_score",
                },
            ),
        )
        # return Response(query)
        return self.execute_query(query, bind_vars=binds)

    def get_cve_bundle(self, cve_id: str):
        query = '''
LET cve_data = (
  FOR doc IN nvd_cve_vertex_collection
  FILTER doc._is_latest AND doc.name == @cve_id
  RETURN doc
)
LET cve_rels = FLATTEN(
    FOR doc IN nvd_cve_edge_collection
    FILTER [doc._from, doc._to] ANY IN cve_data[*]._id
    RETURN [doc, DOCUMENT(doc._from), DOCUMENT(doc._to)]
    )
    
LET cwe_capec = FLATTEN(
    FOR doc IN mitre_cwe_edge_collection
    FILTER [doc._from, doc._to] ANY IN cve_rels[*]._id
    RETURN [doc, DOCUMENT(doc._from), DOCUMENT(doc._to)]
    )
    
LET capec_attack = FLATTEN(
    FOR doc IN mitre_capec_edge_collection
    FILTER [doc._from, doc._to] ANY IN cwe_capec[*]._id
    RETURN [doc, DOCUMENT(doc._from), DOCUMENT(doc._to)]
    )

    
FOR d in UNION_DISTINCT(cve_data, cve_rels, cwe_capec, capec_attack)

LIMIT @offset, @count
//RETURN KEEP(d, 'id', '_stix2arango_note', '_arango_cti_processor_note', 'description')
RETURN KEEP(d, KEYS(d, TRUE))
'''
        return self.execute_query(query, bind_vars=dict(cve_id=cve_id.upper()))

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
            bind_vars['attack_ids'] = value
            filters.append(
                "FILTER doc.external_references[0].external_id in @attack_ids"
            )
        if q := self.query.get('name'):
            bind_vars['name'] = q.lower()
            filters.append('FILTER CONTAINS(LOWER(doc.name), @name)')

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


    def get_object_by_external_id(self, ext_id, relationship_mode=False):
        bind_vars={'@collection': self.collection, 'ext_id': ext_id}
        filters = ['FILTER doc._is_latest']
        for version_param in ['attack_version', 'cwe_version', 'capec_version']:
            if q := self.query.get(version_param):
                bind_vars['mitre_version'] = "version="+q.replace('.', '_').strip('v')
                filters[0] = 'FILTER doc._stix2arango_note == @mitre_version'
                break
        return self.execute_query('''
            FOR doc in @@collection
            FILTER doc.external_references[0].external_id == @ext_id
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
            '''.replace('@filters', '\n'.join(filters)), bind_vars=bind_vars, relationship_mode=relationship_mode)

    def get_cxe_object(self, cve_id, type="vulnerability", var='name', version_param='cve_version', relationship_mode=False):
        bind_vars={'@collection': self.collection, 'obj_name': cve_id, "type":type, 'var':var}
        # return Response(bind_vars)
        filters = ['FILTER doc._is_latest']
        if q := self.query.get(version_param):
            bind_vars['stix_modified'] = q
            filters[0] = 'FILTER doc.modified == @stix_modified'

        return self.execute_query('''
            FOR doc in @@collection
            FILTER doc.type == @type AND doc[@var] == @obj_name
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

    def get_mitre_modified_versions(self, external_id=None, source_name='mitre-attack'):

        query = """
        FOR doc IN @@collection
        FILTER doc.external_references[? ANY FILTER MATCHES(CURRENT, @matcher)] AND STARTS_WITH(doc._stix2arango_note, "version=")
        COLLECT modified = doc.modified INTO group
        SORT modified DESC
        RETURN {modified, versions: UNIQUE(group[*].doc._stix2arango_note)}
        """
        bind_vars = {'@collection': self.collection, 'matcher': dict(external_id=external_id, source_name=source_name)}
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

    def get_cve_versions(self, cve_id: str):
        query = """
        FOR doc IN @@collection
        FILTER doc.name == @cve_id
        SORT doc.modified DESC
        RETURN DISTINCT doc.modified
        """
        bind_vars = {'@collection': self.collection, "cve_id": cve_id.upper()}
        self.container = 'versions'
        versions = self.execute_query(query, bind_vars=bind_vars, paginate=False)
        return Response(dict(latest=versions[0] if versions else None, versions=versions))

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
            bind_vars['ext_ids'] = value
            filters.append(
                "FILTER doc.external_references[0].external_id in @ext_ids"
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

    def get_softwares(self):
        filters = []
        bind_vars = {
                "@collection": 'nvd_cpe_vertex_collection',
                "types": ['software'],
        }
        if value := self.query_as_array('id'):
            bind_vars['ids'] = value
            filters.append(
                "FILTER doc.id in @ids"
            )

        if value := self.query_as_array('cpe_match_string'):
            bind_vars['cpe_match_string'] = value
            filters.append(
                "FILTER @cpe_match_string[? ANY FILTER CONTAINS(doc.cpe, CURRENT)]"
            )
        if value := self.query.get('product_type'):
            bind_vars['product_type'] = value[0]
            filters.append(
                "FILTER @product_type == SPLIT(doc.cpe, ':')[2]"
            )

        if value := self.query.get('product'):
            bind_vars['product'] = value
            filters.append(
                "FILTER @product == SPLIT(doc.cpe, ':')[4]"
            )
        if value := self.query.get('vendor'):
            bind_vars['vendor'] = value
            filters.append(
                "FILTER @vendor == SPLIT(doc.cpe, ':')[3]"
            )

        if q := self.query_as_array('cve_vulnerable'):
            bind_vars['cve_vulnerable'] = q
            filters.append('''
            FILTER cve_matches[? ANY FILTER CURRENT[0]=='is-vulnerable' AND CURRENT[1] IN @cve_vulnerable]
            ''')
        if q := self.query_as_array('in_cve_pattern'):
            bind_vars['in_cve_pattern'] = q
            filters.append('''
            FILTER cve_matches[? ANY FILTER CURRENT[0]=='pattern-contains' AND CURRENT[1] IN @in_cve_pattern]
            ''')

        if q := self.query.get('name'):
            bind_vars['name'] = q
            filters.append('FILTER CONTAINS(doc.name, @name)')

        query = """
            FOR doc in @@collection
            FILTER CONTAINS(@types, doc.type) AND doc._is_latest
            LET cve_matches = (FOR d in nvd_cve_edge_collection FILTER d._to == doc._id AND d.relationship_type IN ['is-vulnerable', 'pattern-contains'] RETURN [d.relationship_type, FIRST(SPLIT(d.description, ' '))])

            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """.replace('@filters', '\n'.join(filters))
        return self.execute_query(query, bind_vars=bind_vars)

    def get_software_by_name(self, cpe_name):
        return self.execute_query('''
        FOR doc in @@collection
        FILTER doc.cpe == @cpe_name AND doc._is_latest
        LIMIT @offset, @count
        RETURN KEEP(doc, KEYS(doc, true))
        ''', bind_vars={'@collection': self.collection, 'cpe_name': cpe_name})

    def get_reports(self, id=None):
        bind_vars = {
                "@collection": self.collection,
                "type": 'report',
        }
        query = """
            FOR doc in @@collection
            FILTER doc.type == @type AND doc._is_latest
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """
        return self.execute_query(query, bind_vars=bind_vars)
    def get_report_by_id(self, id):
        bind_vars = {
                "@collection": self.collection,
                "id": id,
                'type': 'report',
        }
        query = """
            FOR doc in @@collection
            FILTER doc.id == @id AND doc._is_latest AND doc.type == @type
            LIMIT 1
            RETURN KEEP(doc, KEYS(doc, true))
        """
        return self.execute_query(query, bind_vars=bind_vars, paginate=False)
    def remove_report(self, id):
        bind_vars = {
                "@collection": self.collection,
                'report_id': id,
        }
        query = """
            FOR doc in @@collection
            FILTER doc._stixify_report_id == @report_id AND doc._is_latest
            RETURN doc._id
        """
        collections = {}
        out = self.execute_query(query, bind_vars=bind_vars, paginate=False)
        for key in out:
            collection, key = key.split('/', 2)
            collections[collection] = collections.get(collection, [])
            collections[collection].append(key)
        deletion_query = """
            FOR _key in @objects
            REMOVE {_key} IN @@collection
            RETURN _key
        """
        for collection, objects in collections.items():
            bind_vars = {
                "@collection": collection,
                "objects": objects,
            }
            self.execute_query(deletion_query, bind_vars, paginate=False)
    def get_scos(self, matcher={}):
        types = SCO_TYPES
        other_filters = []
        if new_types := self.query_as_array('types'):
            types = types.intersection(new_types)
        bind_vars = {
                "@collection": self.collection,
                "types": list(types),
        }
        if value := self.query.get('value'):
            bind_vars['search_value'] = value
            other_filters.append(
                """
                (
                    CONTAINS(doc.value, @search_value) OR
                    CONTAINS(doc.name, @search_value) OR
                    CONTAINS(doc.path, @search_value) OR
                    CONTAINS(doc.key, @search_value) OR
                    CONTAINS(doc.number, @search_value) OR
                    CONTAINS(doc.string, @search_value) OR
                    CONTAINS(doc.hash, @search_value) OR
                    CONTAINS(doc.symbol, @search_value) OR
                    CONTAINS(doc.address, @search_value) OR
                    (doc.type == 'file' AND @search_value IN doc.hashes)
                )
                """.strip()
            )
        # if post_id := self.query.get('post_id'):
        #     matcher["_obstracts_post_id"] = post_id
        # if report_id := self.query.get('report_id'):
        #     matcher["_stixify_report_id"] = report_id
        if matcher:
            bind_vars['matcher'] = matcher
            other_filters.insert(0, "MATCHES(doc, @matcher)")
        if other_filters:
            other_filters = "FILTER " + " AND ".join(other_filters)
        query = f"""
            FOR doc in @@collection
            FILTER CONTAINS(@types, doc.type) AND doc._is_latest
            {other_filters or ""}
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """
        return self.execute_query(query, bind_vars=bind_vars)
    def get_sdos(self):
        types = SDO_TYPES
        if new_types := self.query_as_array('types'):
            types = types.intersection(new_types)
            
        bind_vars = {
            "@collection": self.collection,
            "types": list(types),
        }
        other_filters = []
        if term := self.query.get('labels'):
            bind_vars['labels'] = term
            other_filters.append("COUNT(doc.labels[* CONTAINS(CURRENT, @labels)]) != 0")
        if term := self.query.get('name'):
            bind_vars['name'] = term
            other_filters.append("CONTAINS(doc.name, @name)")
        if other_filters:
            other_filters = "FILTER " + " AND ".join(other_filters)
        query = f"""
            FOR doc in @@collection
            FILTER doc.type IN @types AND doc._is_latest
            {other_filters or ""}
            LIMIT @offset, @count
            RETURN  KEEP(doc, KEYS(doc, true))
        """
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

    def get_relationships_for_ext_id(self, ext_id):
        bind_vars={'@collection': self.collection, 'ext_matcher': {'external_id': ext_id}}
        filters = ['FILTER doc._is_latest']

        return self.execute_query('''
            LET docs = (FOR doc in @@collection
            FILTER MATCHES(doc.external_references[0], @ext_matcher)
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true)))
            '''.replace('@filters', '\n'.join(filters)), bind_vars=bind_vars)

    def get_relationships(self, docs_query, binds):
        regex = r"KEEP\((\w+),\s*\w+\(.*?\)\)"
        binds['@view'] = settings.VIEW_NAME
        other_filters = []

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

        if term := self.query.get('relationship_type'):
            binds['rel_relationship_type'] = term.lower()
            other_filters.append("FILTER CONTAINS(LOWER(d.relationship_type), @rel_relationship_type)")

        directions = dict(source_ref="_from", target_ref="_to")
        if term := directions.get(self.query.get('relationship_direction')):
            directions = [term]
        else:
            directions = list(directions.values())

        binds['directions'] = directions
        binds['include_embedded_refs'] = self.query_as_bool('include_embedded_refs', True)

        new_query = """
        LET matched_ids = (@docs_query)[*]._id
        FOR d IN @@view
        FILTER d.type == 'relationship' AND VALUES(KEEP(d, @directions)) ANY IN matched_ids AND (NOT d._is_ref OR @include_embedded_refs)
        @other_filters
        LIMIT @offset, @count
        RETURN KEEP(d, KEYS(d, TRUE))
        """.replace('@docs_query', re.sub(regex, lambda x: x.group(1), docs_query.replace('LIMIT @offset, @count', ''))).replace('@other_filters', "\n".join(other_filters))
        return self.execute_query(new_query, bind_vars=binds, container='relationships')
