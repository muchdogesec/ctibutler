import typing
import arango.exceptions
from django.conf import settings
from arango.client import ArangoClient
from arango.database import StandardDatabase
from dogesec_commons.objects import db_view_creator

if typing.TYPE_CHECKING:
    from .. import settings


from stix2arango.stix2arango import Stix2Arango


collections_to_create = [
    "disarm",
    "mitre_atlas",
    "location",
    "mitre_capec",
    "mitre_attack_mobile",
    "mitre_cwe",
    "mitre_attack_ics",
    "mitre_attack_enterprise",
]


def find_missing(collections_to_create):
    client = ArangoClient(settings.ARANGODB_HOST_URL)
    try:
        db = client.db(
            settings.ARANGODB_DATABASE + "_database",
            settings.ARANGODB_USERNAME,
            settings.ARANGODB_PASSWORD,
            verify=True,
        )
    except Exception as e:
        return collections_to_create
    collections = [c["name"] for c in db.collections()]
    return [
        c
        for c in collections_to_create
        if not set([f"{c}_vertex_collection", f"{c}_edge_collection"]).issubset(
            collections
        )
    ]


def create_collections():
    # create db/collections
    for c in find_missing(collections_to_create):
        print(c)
        Stix2Arango(
            settings.ARANGODB_DATABASE,
            collection=c,
            file="no-file",
            username=settings.ARANGODB_USERNAME,
            password=settings.ARANGODB_PASSWORD,
            host_url=settings.ARANGODB_HOST_URL,
        )


def create_analyzer(db, *args, **kwargs):
    try:
        return db.create_analyzer(*args, **kwargs)
    except arango.exceptions.AnalyzerCreateError as e:
        print(e.message)
        if e.error_code != 10:
            raise

def get_semantic_search_properties(db: StandardDatabase):
    create_analyzer(db, 
        "text_en_no_stem_3_10p",
        analyzer_type="text",
        properties={
            "locale": "",
            "case": "lower",
            "accent": False,
            "stemming": False,
            "edgeNgram": {"preserveOriginal": True},
        },
        features=["frequency", "position", "offset", "norm"],
    )
    links = {}
    for c in db.collections():
        if not c["name"].endswith("_collection"):
            continue
        links[c["name"]] = {
            "fields": {
                "description": {"analyzers": ["text_en", "text_en_no_stem_3_10p"]},
                "name": {"analyzers": ["text_en", "text_en_no_stem_3_10p"]},
                "_is_latest": {"analyzers": ["identity"]},
                "_id": {"analyzers": ["identity"]},
                "type": {"analyzers": ["identity"]},
            }
        }
    return {"links": links}


def setup_semantic_search_view():

    semantic_view_name = "semantic_search_view"
    client = ArangoClient(settings.ARANGODB_HOST_URL)
    db = client.db(
        settings.ARANGODB_DATABASE + "_database",
        settings.ARANGODB_USERNAME,
        settings.ARANGODB_PASSWORD,
        verify=True,
    )
    try:
        view = db.view(semantic_view_name)
        db.update_view(semantic_view_name, get_semantic_search_properties(db))
    except:
        db.create_view(
            name=semantic_view_name,
            view_type="arangosearch",
            properties=get_semantic_search_properties(db),
        )


def setup_arangodb():
    create_collections()
    db_view_creator.startup_func()
    setup_semantic_search_view()


if __name__ == "__main__":
    setup_arangodb()
