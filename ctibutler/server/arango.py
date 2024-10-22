from arango import ArangoClient


def get_cves():
    query = """
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'vulnerability' AND doc._is_latest
RETURN doc
    """
    return make_query(query, bind_vars=binds)

