import typing
from django.conf import settings

if typing.TYPE_CHECKING:
    from ..import settings


from stix2arango.stix2arango import Stix2Arango


collections_to_create = ['mitre_atlas', 'tlp', 'location', 'mitre_capec', 'mitre_attack_mobile', 'mitre_cwe', 'mitre_attack_ics', 'mitre_attack_enterprise']

    
def create_collections():

    #create db/collections
    for c in collections_to_create:
        Stix2Arango(settings.ARANGODB_DATABASE, collection=c, file='no-file', username=settings.ARANGODB_USERNAME, password=settings.ARANGODB_PASSWORD, host_url=settings.ARANGODB_HOST_URL)
   
   
if __name__ == '__main__':
    create_collections()



