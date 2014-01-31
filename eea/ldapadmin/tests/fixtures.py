ldap_data = {
    'ou=Roles,o=EIONET,l=Europe': {
        'description': ["Roles"],
        'uniqueMember': [
            'uid=userone,ou=Users,o=EIONET,l=Europe',
            'uid=usertwo,ou=Users,o=EIONET,l=Europe',
            'uid=userthree,ou=Users,o=EIONET,l=Europe',
            'uid=userfour,ou=Users,o=EIONET,l=Europe',
            'cn=air_agency,ou=Organisations,o=EIONET,l=Europe',
        ]
    },
    'ou=Organisations,o=EIONET,l=Europe': {},
    'cn=A,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [A]"],
        'uniqueMember': [
            'uid=userone,ou=Users,o=EIONET,l=Europe',
            'uid=usertwo,ou=Users,o=EIONET,l=Europe',
            'uid=userthree,ou=Users,o=EIONET,l=Europe',
            'cn=air_agency,ou=Organisations,o=EIONET,l=Europe',
        ],
    },
    'cn=A-B,cn=A,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [A B]"],
        'uniqueMember': [
            'uid=usertwo,ou=Users,o=EIONET,l=Europe',
        ],
    },
    'cn=A-C,cn=A,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [A C]"],
        'uniqueMember': [
            'uid=userthree,ou=Users,o=EIONET,l=Europe',
            'cn=air_agency,ou=Organisations,o=EIONET,l=Europe',
        ],
    },
    'cn=K,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [K]"],
        'uniqueMember': [''],
    },
    'cn=K-L,cn=K,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [K L]"],
        'uniqueMember': [''],
    },
    'cn=K-L-O,cn=K-L,cn=K,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [K L O]"],
        'uniqueMember': [''],
    },
    'cn=K-M,cn=K,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [K M]"],
        'uniqueMember': [''],
    },
    'cn=K-M-O,cn=K-M,cn=K,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [K M O]"],
        'uniqueMember': [
            'uid=userfour,ou=Users,o=EIONET,l=Europe',
        ],
    },
    'cn=K-N,cn=K,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [K N]"],
        'uniqueMember': [''],
    },
    'cn=K-N-O,cn=K-N,cn=K,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [K N O]"],
        'uniqueMember': [''],
    },
    'cn=K-N-O-P,cn=K-N-O,cn=K-N,cn=K,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [K N O P]"],
        'uniqueMember': [''],
    },
    'cn=K-N-T,cn=K-N,cn=K,ou=Roles,o=EIONET,l=Europe': {
        'description': ["Role [K N T]"],
        'uniqueMember': [''],
    },
    'uid=userone,ou=Users,o=EIONET,l=Europe': {
        'cn': ['User One'],
        'mail': ['user_one@example.com'],
        'telephoneNumber': ['555 1234 1'],
        'o': ['independent consultant'],
    },
    'uid=usertwo,ou=Users,o=EIONET,l=Europe': {
        'cn': ['User Two'],
        'mail': ['user_two@example.com'],
        'telephoneNumber': ['555 1234 2'],
        'o': ['Testers Club'],
    },
    'uid=userthree,ou=Users,o=EIONET,l=Europe': {
        'cn': ['User Three'],
        'mail': ['user_three@example.com'],
        'telephoneNumber': ['555 1234 3'],
        'o': ['EEA person'],
    },
    'uid=userfour,ou=Users,o=EIONET,l=Europe': {
        'cn': ['User Four'],
    },
    'cn=air_agency,ou=Organisations,o=EIONET,l=Europe': {
        'objectClass': ['top', 'groupOfUniqueNames', 'labeledURIObject'],
        'o': ['Agency for Air Studies'],
        'labeledURI': ['http://www.air_agency.example.com'],
        'cn': ['air_agency'],
        'uniqueMember': ['uid=usertwo,ou=Users,o=EIONET,l=Europe',
                         'uid=userfour,ou=Users,o=EIONET,l=Europe'],
    },
}
