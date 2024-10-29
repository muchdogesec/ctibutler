import typing
from django.conf import settings
from arango.client import ArangoClient

if typing.TYPE_CHECKING:
    from ..import settings


from stix2arango.stix2arango import Stix2Arango


collections_to_create = ['disarm', 'mitre_atlas', 'tlp', 'location', 'mitre_capec', 'mitre_attack_mobile', 'mitre_cwe', 'mitre_attack_ics', 'mitre_attack_enterprise']

def find_missing(collections_to_create):
    client = ArangoClient(settings.ARANGODB_HOST_URL)
    try:
        db = client.db(settings.ARANGODB_DATABASE+"_database", settings.ARANGODB_USERNAME, settings.ARANGODB_PASSWORD, verify=True)
    except Exception as e:
        return collections_to_create
    collections = [c["name"] for c in db.collections()]
    return [
        c for c in collections_to_create
            if not set([f"{c}_vertex_collection", f"{c}_edge_collection"]).issubset(collections)
        ]    
def create_collections():

    #create db/collections
    for c in find_missing(collections_to_create):
        print(c)
        Stix2Arango(settings.ARANGODB_DATABASE, collection=c, file='no-file', username=settings.ARANGODB_USERNAME, password=settings.ARANGODB_PASSWORD, host_url=settings.ARANGODB_HOST_URL)
   
   
if __name__ == '__main__':
    create_collections()



