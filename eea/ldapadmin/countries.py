import os.path
import json
import time

import sparql

from eea.ldapadmin.constants import SPARQL_ENDPOINT, SPARQL_QUERY
from eea.ldapadmin.constants import LDAP_DISK_STORAGE


_country_storage = {
    'time': 0,
    'data': {},
    'timeout': 3600*24, # seconds
}
COUNTRIES = _country_storage['data'] # shortcut
PSEUDO_COUNTRIES = [('eu', {
                            'code': 'eu',
                            'name': 'European Union organisation',
                            'pub_code': 'eu',
                            'eu': True,
                            'eea': True,
                            'eionet': True,
                            'eun22': True,
                              }),
                    ('int', {
                            'code': 'int',
                            'name': 'International or multinat. organisation',
                            'pub_code': '',
                            'eu': False,
                            'eea': False,
                            'eionet': False,
                            'eun22': False,
                    })
                   ]

DUMMY = {'code': '',
         'name': '',
         'pub_code': '',
         'eu': False,
         'eea': False,
         'eionet': False,
         'eun22': False,
         }



def update_countries():
    """ Return country data from EEA Semantic Service and store them in json """
    s = sparql.Service(SPARQL_ENDPOINT)
    results = [i for i in s.query(SPARQL_QUERY).fetchone()]
    countries = []
    if len(results) > 0:
        for item in results:
            (code, name, pub_code, eu, eea, eionet, eun22) = item
            countries.append({
                'code': code.value.lower(),
                'name': name.value,
                'pub_code': pub_code.value,
                'eu': eu.value == 'Yes',
                'eea': eea.value == 'Yes',
                'eionet': eionet.value == 'Yes',
                'eun22': eun22.value == 'Yes',
            })
    f = open(os.path.join(LDAP_DISK_STORAGE, "countries.json"), "w")
    json.dump(countries, f)
    f.close()


def load_countries():
    """ Load countries from json file in memory """
    try:
        f = open(os.path.join(LDAP_DISK_STORAGE, "countries.json"), "r")
        data = json.load(f)
    except (IOError, ValueError) as e:
        update_countries()
        return load_countries()
    else:
        _country_storage['data'].clear()
        _country_storage['data'].update([(x['code'], x) for x in data])
        _country_storage['time'] = time.time()
        f.close()


def get_country(code):
    """ Return country object for given code """
    code = code.lower()
    pseudos = dict(PSEUDO_COUNTRIES)
    if code in pseudos:
        return pseudos[code]
    if time.time() - _country_storage['time'] > _country_storage['timeout']:
        load_countries()
    return COUNTRIES.get(code.lower(), DUMMY)


def get_country_options(country=None):
    """ Return the list of options for country field. Pseudo-countries first,
    then countries sorted by name """
    countries = COUNTRIES.items()
    if country:
        return [country_data for country_data in countries+PSEUDO_COUNTRIES
                if country_data[0] == country]
    countries.sort(key=lambda x: x[1]['name'])
    return PSEUDO_COUNTRIES + countries
