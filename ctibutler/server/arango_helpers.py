import contextlib
from types import SimpleNamespace
import typing
from django.conf import settings
from ctibutler.server.utils import Pagination, Response
from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from dogesec_commons.objects.helpers import ArangoDBHelper as DSC_ArangoDBHelper
from rest_framework import exceptions
from ctibutler.server import utils
from arango.database import StandardDatabase
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
    "x-mitre-tactic",
    'x-mitre-asset'
]
)

ATTACK_FORMS = {
    "Tactic": [dict(type='x-mitre-tactic')],
    "Technique": [dict(type='attack-pattern', x_mitre_is_subtechnique=False), dict(type='attack-pattern', x_mitre_is_subtechnique=None)],
    "Sub-technique": [dict(type='attack-pattern', x_mitre_is_subtechnique=True)],
    "Mitigation": [dict(type='course-of-action')],
    "Group": [dict(type='intrusion-set')],
    "Software": [dict(type='malware'), dict(type='tool')],
    "Campaign": [dict(type='campaign')],
    "Data Source": [dict(type='x-mitre-data-source')],
    "Data Component": [dict(type='x-mitre-data-component')],
    "Asset": [dict(type='x-mitre-asset')],
}


ATLAS_FORMS = {
    "Tactic": [dict(type='x-mitre-tactic')],
    "Technique": [dict(type='attack-pattern', x_mitre_is_subtechnique=False), dict(type='attack-pattern', x_mitre_is_subtechnique=None)],
    "Sub-technique": [dict(type='attack-pattern', x_mitre_is_subtechnique=True)],
    "Mitigation": [dict(type='course-of-action')],
}


DISARM_FORMS = {
    "Tactic": [dict(type='x-mitre-tactic')],
    "Technique": [dict(type='attack-pattern', x_mitre_is_subtechnique=False), dict(type='attack-pattern', x_mitre_is_subtechnique=None)],
    "Sub-technique": [dict(type='attack-pattern', x_mitre_is_subtechnique=True)],
}

LOCATION_TYPES = set([
    'location'
])
CWE_TYPES = set([
    "weakness",
    "grouping",
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

CTI_SORT_FIELDS = [
    "modified_descending",
    "modified_ascending",
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
    "type_ascending",
    "type_descending",
]

OBJECT_TYPES = SDO_TYPES.union(SCO_TYPES).union(["relationship"])
SEMANTIC_SEARCH_TYPES = CAPEC_TYPES.union(LOCATION_TYPES, SOFTWARE_TYPES, ATTACK_TYPES, DISARM_TYPES, CWE_TYPES, TLP_TYPES, ATLAS_TYPES)
SEMANTIC_SEARCH_SORT_FIELDS = [
    "modified_descending",
    "modified_ascending",
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
    "type_ascending",
    "type_descending",
]
KNOWLEDGE_BASE_TO_COLLECTION_MAPPING = {
    'disarm': [
        "disarm_vertex_collection",
    ],
    'location':[
        "location_vertex_collection",
    ],
    'atlas': [

        "mitre_atlas_vertex_collection",
    ],
    'attack': [
        "mitre_attack_enterprise_vertex_collection",
        "mitre_attack_ics_vertex_collection",
        "mitre_attack_mobile_vertex_collection",
    ],
    'attack-ics': [
        "mitre_attack_ics_vertex_collection",
    ],
    'attack-mobile': [
        "mitre_attack_mobile_vertex_collection",
    ],
    'attack-enterprise': [
        "mitre_attack_enterprise_vertex_collection",
    ],
    'capec': [
        "mitre_capec_vertex_collection",
    ],
    'cwe': [
        "mitre_cwe_vertex_collection",
    ]

}
COLLECTION_TO_KNOWLEDGE_BASE_MAPPING = {v: k for k, vv in KNOWLEDGE_BASE_TO_COLLECTION_MAPPING.items() for v in vv}
ATTACK_SORT_FIELDS = CTI_SORT_FIELDS+['attack_id_ascending', 'attack_id_descending']

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

from functools import lru_cache
@lru_cache
def _get_versions(collection, arango_revision):
    print("checking version: ", arango_revision)
    helper = ArangoDBHelper(collection, SimpleNamespace(GET=dict(), query_params=SimpleNamespace(dict=dict)))
    query = """
        FOR doc IN @@collection
        FILTER STARTS_WITH(doc._stix2arango_note, "version=")
        RETURN DISTINCT doc._stix2arango_note
        """
    bind_vars = {'@collection': collection}
    versions = helper.execute_query(query, bind_vars=bind_vars, paginate=False)
    versions = helper.clean_and_sort_versions(versions)
    return versions

def get_versions(collection):
    #cache for revision
    try:
        helper = ArangoDBHelper(collection, SimpleNamespace(GET=dict(), query_params=SimpleNamespace(dict=dict)))
        rev = helper.db.collection(collection).revision()
        return _get_versions(collection, rev)
    except:
        return []

def get_latest_version(collection):
    versions = get_versions(collection) or ['']
    return versions[0]

class ArangoDBHelper(DSC_ArangoDBHelper):
    max_page_size = settings.MAXIMUM_PAGE_SIZE
    page_size = settings.DEFAULT_PAGE_SIZE
    semantic_search_view = 'semantic_search_view'
    SEMANTIC_SEARCH_QUERY_TEXT = """
    (
        ANALYZER(TOKENS(@search_param, "text_en") ALL IN doc.name, "text_en") OR ANALYZER(TOKENS(@search_param, "text_en") ALL IN doc.description, "text_en")
        OR ANALYZER(TOKENS(@search_param, "text_en_no_stem_3_10p") ALL IN doc.name, "text_en_no_stem_3_10p") OR ANALYZER(TOKENS(@search_param, "text_en_no_stem_3_10p") ALL IN doc.description, "text_en_no_stem_3_10p")
    )
    """

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
                    If `ignore_embedded_relationships` is set to `false` in the POST request to download data, stix2arango will create SROS for embedded relationships (e.g. from `created_by_refs`). You can choose to show them (`true`) or hide them (`false`) using this parameter. Default value if not passed is `true`.  This is a arango_cti_processor setting.
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
            ),
            OpenApiParameter(
                "_arango_cti_processor_note",
                description="Filter results by `_arango_cti_processor_note`"
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

    DB_NAME = f"{settings.ARANGODB_DATABASE}_database"
    def __init__(self, collection, request, container='objects') -> None:

        super().__init__(collection, request, container)
        self.container = container

    default_objects: list[str] = []

    @classmethod
    def get_default_objects(cls, db: StandardDatabase):
        non_clear_tlp_markers = [
            "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
            "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
            "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
            "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
        ]
        if cls.default_objects:
            return cls.default_objects
        cls.default_objects = list(db.aql.execute("""
        FOR d IN @@view
        SEARCH d.type IN ['identity', 'marking-definition', 'extension-definition']
        FILTER d.id NOT IN @non_clear_tlp_markers
        RETURN d._id
        """, bind_vars={'@view': settings.VIEW_NAME, 'non_clear_tlp_markers': non_clear_tlp_markers}))
        return cls.default_objects

    def execute_query(self, query, bind_vars={}, paginate=True, container=None):
        if paginate:
            bind_vars['offset'], bind_vars['count'] = self.get_offset_and_count(self.count, self.page)
        cursor = self.db.aql.execute(query, bind_vars=bind_vars, count=True, full_count=True)
        if paginate:
            return self.get_paginated_response(container or self.container, list(cursor), self.page, self.page_size, cursor.statistics()["fullCount"])
        return list(cursor)

    def get_attack_objects(self, matrix):
        filters = []
        types = ATTACK_TYPES
        if new_types := self.query_as_array('types'):
            types = types.intersection(new_types)
        collection_name = f'mitre_attack_{matrix}_vertex_collection'
        bind_vars = {
                "types": list(types),
        }

        if attack_forms := self.query_as_array('attack_type'):
            form_list = []
            for form in attack_forms:
                form_list.extend(ATTACK_FORMS.get(form, []))

            if form_list:
                filters.append('FILTER @attack_form_list[? ANY FILTER MATCHES(doc, CURRENT)]')
                bind_vars['attack_form_list'] = form_list

        if q := self.query.get(f'attack_version', get_latest_version(collection_name)):
            bind_vars['mitre_version'] = "version="+q.replace('.', '_').strip('v')
            filters.append('FILTER doc._stix2arango_note == @mitre_version')
        else:
            filters.append('FILTER doc._is_latest')

        if value := self.query_as_array('id'):
            bind_vars['ids'] = value
            filters.append(
                "FILTER doc.id in @ids"
            )

        if not self.query_as_bool('include_deprecated', False):
            filters.append('FILTER NOT doc.x_mitre_deprecated AND doc.x_capec_status NOT IN ["Deprecated", "Obsolete"]')
        if not self.query_as_bool('include_revoked', False):
            filters.append('FILTER NOT doc.revoked')

        if value := self.query_as_array('attack_id'):
            bind_vars['attack_ids'] = [v.lower() for v in value]
            filters.append(
                "FILTER LOWER(doc.external_references[0].external_id) in @attack_ids"
            )

        if q := self.query.get('alias'):
            bind_vars['alias'] = q.lower()
            filters.append('FILTER APPEND(doc.aliases, doc.x_mitre_aliases)[? ANY FILTER CONTAINS(LOWER(CURRENT), @alias)]')

        search_filters = ['doc.type IN @types', 'ANALYZER(STARTS_WITH(doc._id, @collection_name), "identity")']

        if q := self.query.get("text"):
            bind_vars['search_param'] = q
            search_filters.append(self.SEMANTIC_SEARCH_QUERY_TEXT)

        bind_vars.update(collection_name=collection_name)
        sort_statement = self.get_sort_stmt(ATTACK_SORT_FIELDS, customs=dict(attack_id='doc.external_references[0].external_id'))

        return self.generic_query(self.semantic_search_view, search_filters, filters, bind_vars, sort_statement=sort_statement)

    def get_object_by_external_id(self, ext_id: str, version_param, relationship_mode=False, revokable=False, bundle=False, nav_mode=False):
        bind_vars={'@collection': self.collection, 'ext_id': ext_id.lower(), 'keep_values': None}
        filters = ['FILTER doc._stix2arango_note == @mitre_version']
        mitre_version: str = None
        if q := self.query.get(version_param, get_latest_version(self.collection)):
            mitre_version = q
            bind_vars.update(mitre_version="version="+mitre_version.replace('.', '_').strip('v'))
        else:
            filters[0] = 'FILTER doc._is_latest'

        if revokable:
            bind_vars['include_deprecated'] = self.query_as_bool('include_deprecated', False)
            bind_vars['include_revoked'] = self.query_as_bool('include_revoked', False)
            filters.append('FILTER (@include_revoked OR NOT doc.revoked) AND (@include_deprecated OR NOT doc.x_mitre_deprecated)')

        main_filter = "FILTER LOWER(doc.external_references[0].external_id) == @ext_id"
        with contextlib.suppress(Exception):
            _, _ = ext_id.split('--')
            main_filter = "FILTER doc.id == @ext_id"

        query = '''
            FOR doc in @@collection
            #main_filter
            #filters
            LIMIT @offset, @count
            RETURN KEEP(doc, @keep_values || APPEND(KEYS(doc, TRUE), '_stix2arango_note'))
            '''
        query = query.replace('#main_filter', main_filter).replace('#filters', '\n'.join(filters))
        if bundle or relationship_mode:
            bind_vars.update(keep_values=['_id', '_stix2arango_note'])
        if nav_mode:
            bind_vars.update(keep_values=['_id', 'name', 'external_references', 'id', 'type', '_stix2arango_note'])
        bind_vars.update(offset=0, count=None)
        matches = self.execute_query(query, bind_vars=bind_vars, paginate=False)

        if nav_mode:
            return self.get_nav(matches)

        matches = sorted(matches, key=lambda m: utils.split_mitre_version(m.pop('_stix2arango_note', '=').split("=", 1)[-1]), reverse=True)
        matches = matches[:1]

        if bundle:
            return self.get_bundle(matches)
        if relationship_mode:
            return self.get_relationships(matches)

        return self.get_paginated_response(self.container, matches, self.page, self.page_size, len(matches))

    def get_mitre_versions(self):
        versions = get_versions(self.collection)
        return Response(dict(latest=versions[0] if versions else None, versions=versions))

    def get_mitre_modified_versions(self, external_id: str=None, source_name='mitre-attack'):
        main_filter = "doc.external_references[? ANY FILTER LOWER(CURRENT.external_id) == @matcher.external_id AND @matcher.source_name == CURRENT.source_name]"
        with contextlib.suppress(Exception):
            _, _ = external_id.split('--')
            main_filter = "doc.id == @matcher.external_id"
        query = """
        FOR doc IN @@collection
        FILTER #main_filter AND STARTS_WITH(doc._stix2arango_note, "version=")
        FILTER (@include_revoked OR NOT doc.revoked) AND (@include_deprecated OR NOT doc.x_mitre_deprecated) // for MITRE ATT&CK, check if revoked
        COLLECT modified = doc.modified INTO group
        SORT modified DESC
        RETURN {modified, versions: UNIQUE(group[*].doc._stix2arango_note)}
        """.replace('#main_filter', main_filter)
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

    def clean_and_sort_versions(self, versions, replace_underscore=True):
        replace_character = '.' if replace_underscore else '_'
        versions = sorted([
            v.split("=")[1].replace('_', replace_character)
            for v in versions
        ], key=utils.split_mitre_version, reverse=True)
        return [f"{v}" for v in versions]

    def get_weakness_or_capec_objects(self, lookup_kwarg, types=CWE_TYPES, more_binds={}, more_filters=[], forms={}):
        version_param = lookup_kwarg.replace('_id', '_version')
        filters = []
        if new_types := self.query_as_array('types'):
            types = types.intersection(new_types)

        bind_vars = {
                # "@collection": self.collection,
                "types": list(types),
                **more_binds
        }
        if q := self.query.get(version_param, get_latest_version(self.collection)):
            bind_vars['mitre_version'] = "version="+q.replace('.', '_').strip('v')
            filters.append('FILTER doc._stix2arango_note == @mitre_version')
        else:
            filters.append('FILTER doc._is_latest')

        if value := self.query_as_array('id'):
            bind_vars['ids'] = value
            filters.append(
                "FILTER doc.id in @ids"
            )

        if not self.query_as_bool('include_deprecated'):
            filters.append('FILTER doc.x_capec_status NOT IN ["Deprecated", "Obsolete"]')

        if generic_forms := self.query_as_array(lookup_kwarg.replace('_id', '_type')):
            form_list = []
            for form in generic_forms:
                form_list.extend(forms.get(form, []))

            if form_list:
                filters.append('FILTER @generic_form_list[? ANY FILTER MATCHES(doc, CURRENT)]')
                bind_vars['generic_form_list'] = form_list
        if q := self.query.get('name'):
            bind_vars['name'] = q.lower()
            filters.append('FILTER CONTAINS(LOWER(doc.name), @name)')

        if value := self.query_as_array(lookup_kwarg):
            bind_vars['ext_ids'] = [v.lower() for v in value]
            filters.append(
                "FILTER LOWER(doc.external_references[0].external_id) in @ext_ids"
            )
        search_filters = ['doc.type IN @types', 'ANALYZER(STARTS_WITH(doc._id, @collection_name), "identity")']
        bind_vars.update(collection_name=self.collection)

        if q := self.query.get("text"):
            bind_vars['search_param'] = q
            search_filters.append(self.SEMANTIC_SEARCH_QUERY_TEXT)
        filters.extend(more_filters)
        sort_statement = self.get_sort_stmt(
            CTI_SORT_FIELDS
            + [
                lookup_kwarg + "_descending",
                lookup_kwarg + "_ascending",
                "location_type_ascending",
                "location_type_descending",
            ],
            customs={
                lookup_kwarg: "doc.external_references[0].external_id",
                "location_type": 'FIRST(doc.external_references[* FILTER CURRENT.source_name == "type"]).external_id',
            },
        )
        return self.generic_query(self.semantic_search_view, search_filters, filters, bind_vars, sort_statement=sort_statement)

    def get_relationships(self, matches):
        binds = {
            '@view': settings.VIEW_NAME,
            'matches': matches
        }
        other_filters = []

        if term := self.query.get('relationship_type'):
            binds['rel_relationship_type'] = term.lower()
            other_filters.append("FILTER CONTAINS(LOWER(d.relationship_type), @rel_relationship_type)")

        if term := self.query.get('_arango_cti_processor_note'):
            binds['rel_acp_note'] = term.lower()
            other_filters.append("FILTER CONTAINS(LOWER(d._arango_cti_processor_note), @rel_acp_note)")

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
            case "source_ref":
                direction_query = "d._from IN matched_ids"
            case 'target_ref':
                direction_query = 'd._to IN matched_ids'
            case _:
                direction_query = 'd._from IN matched_ids OR d._to IN matched_ids'

        if self.query_as_bool('include_embedded_refs', True):
            embedded_refs_query = ''
        else:
            embedded_refs_query = 'AND d._is_ref != TRUE'

        new_query = """
        LET matched_ids = @matches[*]._id
        FOR d IN @@view
        SEARCH d.type == 'relationship' AND (#direction_query) #include_embedded_refs
        #other_filters
        COLLECT id = d.id INTO docs LET d = FIRST(FOR dd IN docs[*].d SORT dd.modified DESC, dd._record_modified DESC LIMIT 1 RETURN dd) // dedeuplicate across multiple actip runs
        LIMIT @offset, @count
        RETURN KEEP(d, KEYS(d, TRUE))
        """ \
            .replace('#other_filters', "\n".join(other_filters)) \
            .replace('#direction_query', direction_query) \
            .replace('#include_embedded_refs', embedded_refs_query)

        return self.execute_query(new_query, bind_vars=binds, container='relationships')

    def get_nav(self, matches):
        binds = {
            '@view': settings.VIEW_NAME,
            'matches': matches
        }
        if not matches:
            raise exceptions.NotFound('not found')
        matched_object = matches[0]
        if matched_object['type'] not in ['tool', 'malware', 'intrusion-set', 'campaign', 'course-of-action', 'x-mitre-asset']:
            raise exceptions.ParseError(f'object of type `{matched_object["type"]}` not supported')
        version = matched_object['_stix2arango_note'].split('=')[-1]
        new_query = """
        LET matched_ids = @matches[*]._id
        FOR d IN @@view
        SEARCH d.type == 'relationship' AND (d._from IN matched_ids OR d._to IN matched_ids)
        RETURN [d._from, d._to, d.description]
        """
        relationships = self.execute_query(new_query, bind_vars=binds, paginate=False)
        techniques = {}
        for obj in relationships:
            stix_id = None
            if 'attack-pattern' in obj[0]:
                stix_id = obj[0]
            elif "attack-pattern" in obj[1]:
                stix_id = obj[1]
            if stix_id:
                techniques[stix_id] = {
                    "comment": obj[2],
                    "score": 100,
                    "showSubtechniques": True,
                }
        final_query = """
        FOR d IN @@view
        SEARCH d._id IN @technique_stix_ids
        RETURN [d._id, d.external_references[0].external_id]
        """
        for stix_id, ext_id in self.execute_query(final_query, bind_vars={'@view': settings.VIEW_NAME, 'technique_stix_ids': list(techniques)}, paginate=False):
            techniques[stix_id].update(techniqueID=ext_id)

        name = matched_object['name']
        attack_id = ''
        if matched_object['external_references'] and matched_object['external_references'][0]['source_name'] == 'mitre-attack':
            attack_id = matched_object['external_references'][0]['external_id']
        domain = self.collection.split('_')[2]

        nav_retval = {
            "description": f"Techniques used by {name} ({attack_id})",
            "name": attack_id,
            "domain": f'{domain}-attack',
            "versions": {
                "layer": "4.5",
                "attack": version.replace('_', '.'),
                "navigator": "5.1.0"
            },
                "techniques": [t for t in techniques.values() if t.get('techniqueID')],
                "gradient": {
                    "colors": [
                        "#ffffff",
                        "#ff6666"
                    ],
                    "minValue": 0,
                    "maxValue": 100
                },
                "legendItems": [],
                "metadata": [
                    {
                        "name": "stix_id",
                        "value": matched_object['id']
                    },
                    {
                        "name": "attack_id",
                        "value": attack_id
                    }
                ],
                "links": [
                    {
                        "label": "cti_butler",
                        "url": "https://app.ctibutler.com"
                    }
                ],
                "layout": {
                    "layout": "side"
                }
            }

        return Response(nav_retval)

    def get_bundle(self, matches):
        binds = {
            '@view': settings.VIEW_NAME,
            'matches': matches
        }
        more_search_filters = []
        late_filters = []
        if not matches:
            raise exceptions.NotFound({'error': 'No such object'})

        if not self.query_as_bool('include_embedded_refs', True):
            more_search_filters.append('d._is_ref != TRUE')

        if not self.query_as_bool('include_embedded_sros', True):
            late_filters.append('d._is_ref != TRUE')

        if types := self.query_as_array('types'):
            late_filters.append('FILTER d.type IN @types')
            binds['types'] = types

        binds['more_bundle_ids'] = [x for x in self.get_default_objects(self.db) if x.startswith(self.collection)]

        query = '''
    LET matched_ids = @matches[*]._id

    LET bundle_ids = FLATTEN(
        FOR d IN @@view SEARCH d.type == 'relationship' AND (d._from IN matched_ids OR d._to IN matched_ids) #more_search_filters
        COLLECT id = d.id INTO docs LET d = FIRST(FOR dd IN docs[*].d SORT dd.modified DESC, dd._record_modified DESC LIMIT 1 RETURN dd) // dedeuplicate across multiple actip runs
        RETURN [d._id, d._from, d._to]
    ) 
    
    FOR d IN @@view SEARCH d._id IN UNION(bundle_ids, matched_ids, @more_bundle_ids)
    #late_filters
    COLLECT id = d.id INTO docs LET d = FIRST(FOR dd IN docs[*].d SORT dd.modified DESC, dd._record_modified DESC LIMIT 1 RETURN dd) // dedeuplicate across multiple actip runs
    LIMIT @offset, @count
    RETURN KEEP(d, KEYS(d, TRUE))
'''
        query = query \
                    .replace('#more_search_filters', "" if not more_search_filters else f" AND {' and '.join(more_search_filters)}") \
                    .replace('#late_filters', '\n'.join(late_filters))
        return self.execute_query(query, bind_vars=binds)

    def semantic_search(self):
        binds = {
        }
        search_filters = []
        if search_param:= self.query.get('text'):
            search_filters.append(self.SEMANTIC_SEARCH_QUERY_TEXT)
            binds.update(search_param=search_param)

        search_filters.append('doc._is_latest == TRUE')

        if types := self.query_as_array('types'):
            binds['types'] = types
            search_filters.append('doc.type IN @types')

        collections = set()
        if qq := self.query_as_array('knowledge_bases'):
            for q in qq:
                collections.update(KNOWLEDGE_BASE_TO_COLLECTION_MAPPING.get(q, []))
            binds['knowledge_base_collections'] = list(collections)
            search_filters.append('ANALYZER(STARTS_WITH(doc._id, @knowledge_base_collections), "identity")')
        extra_filters = []

        if not self.query_as_bool('include_deprecated', False):
            extra_filters.append('FILTER doc.x_mitre_deprecated != TRUE AND doc.x_capec_status NOT IN ["Deprecated", "Obsolete"]')
        if not self.query_as_bool('include_revoked', False):
            extra_filters.append('FILTER doc.revoked != TRUE')
        keep_verb=None
        if show_knowledgebase := self.query_as_bool('show_knowledgebase', False):
            keep_verb = 'KEEP(doc, APPEND(KEYS(doc, TRUE), "_id"))'
        resp = self.generic_query(self.semantic_search_view, search_filters, extra_filters, binds, return_verb=keep_verb)
        if show_knowledgebase:
            self.add_knowledgebase_name(resp.data['objects'])
        return resp

    def generic_query(self, collection_or_view, search_filters: list[str], extra_filters: list[str], binds, sort_statement='', sort_fields=SEMANTIC_SEARCH_SORT_FIELDS, return_verb=None, use_limit=True):
        search_filters_str = ''
        binds['@collection_or_view'] = collection_or_view
        return_verb = return_verb or 'KEEP(doc, KEYS(doc, TRUE))'
        kwargs = dict(paginate=False)

        if not use_limit:
            limit_stmt = ''
        elif isinstance(use_limit, str):
            limit_stmt = use_limit
        else:
            limit_stmt = 'LIMIT @offset, @count'
            kwargs.update(paginate=True)

        if not sort_statement:
            sort_statement = self.get_sort_stmt(sort_fields)

        query = """
            FOR doc IN @@collection_or_view
            #SEARCH
            #FILTER
            #sort_stmt
            #LIMIT
            RETURN #return_verb
        """
        if search_filters:
            search_filters_str = 'SEARCH ' + (' AND '.join(search_filters))
        query = query.replace('#SEARCH', search_filters_str) \
            .replace('#FILTER', '\n'.join(extra_filters)) \
            .replace('#return_verb', return_verb).replace('#sort_stmt', sort_statement) \
            .replace('#LIMIT', limit_stmt)
        resp = self.execute_query(query, bind_vars=binds, **kwargs)
        return resp

    @staticmethod
    def add_knowledgebase_name(objects):
        for obj in objects:
            collection_name, _, _ = obj.pop('_id').partition('/')
            obj['knowledgebase_name'] = COLLECTION_TO_KNOWLEDGE_BASE_MAPPING[collection_name]
