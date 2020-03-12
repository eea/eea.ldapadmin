import os

from App.config import getConfiguration

cfg = getConfiguration()
if hasattr(cfg, 'environment'):
    cfg.environment.update(os.environ)

# constant defined in env
NETWORK_NAME = getattr(cfg, 'environment', {}).get('NETWORK_NAME', 'Eionet')
LDAP_DISK_STORAGE = getattr(cfg, 'environment', {}).get(
    'LDAP_DISK_STORAGE', os.environ.get('LDAP_DISK_STORAGE', ''))

SPARQL_QUERY = """
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX eea: <http://rdfdata.eionet.europa.eu/eea/ontology/>

        SELECT DISTINCT ?code ?countryname ?publishingCode
          IF(bound(?eumember),'Yes','') AS ?eu
          IF(bound(?eeamember),'Yes','') AS ?eea
          IF(bound(?eionetmember),'Yes','') AS ?eionet
          IF(bound(?eun22member),'Yes','') AS ?eun22
        WHERE {
          ?ucountry a eea:Country ;
                    eea:code ?code;
                    eea:publishingCode ?publishingCode;
                    rdfs:label ?countryname
         OPTIONAL { <http://rdfdata.eionet.europa.eu/eea/countries/EU> skos:member ?ucountry, ?eumember }
         OPTIONAL { <http://rdfdata.eionet.europa.eu/eea/countries/EUN22> skos:member ?ucountry, ?eun22member }
         OPTIONAL { <http://rdfdata.eionet.europa.eu/eea/countries/EEA> skos:member ?ucountry, ?eeamember }
         OPTIONAL { <http://rdfdata.eionet.europa.eu/eea/countries/EIONET> skos:member ?ucountry, ?eionetmember }
        }"""  # noqa: E501

SPARQL_ENDPOINT = 'http://semantic.eea.europa.eu/sparql'

USER_INFO_KEYS = [
    'status', 'last_name', 'uid', 'reasonToCreate', 'full_name', 'id',
    'first_name', 'organisation', 'department', 'email', 'metadata', 'dn',
    'fax', 'postal_address', 'phone', 'employeeNumber', 'modifyTimestamp',
    'mobile', 'full_name_native', 'pwdChangedTime', 'url', 'createTimestamp',
    'job_title', 'search_helper']
