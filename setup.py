from setuptools import setup, find_packages

setup(name='eea.ldapadmin',
      version='1.5.28',
      author='Eau de Web',
      author_email='office@eaudeweb.ro',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'eea.usersdb>=1.3.35',
          'naaya.ldapdump',

          'BeautifulSoup',
          'lxml',

          'deform==0.9.4',
          'colander==1.7.0',
          'jellyfish==0.2.0',

          'xlrd>=0.9.3',
          'xlwt',
          'unidecode==1.0.23',

          'requests==2.18.4',
          'sparql-client',
          'python-dateutil',
          'pyDNS',
          'transliterate',
          'validate-email>=edw.1.3.1',
      ],
      entry_points={'console_scripts':
                    ['dump_ldap = eea.ldapadmin.ldapdump:dump_ldap',
                     'update_countries = '
                        'eea.ldapadmin.countries:update_countries',
                     'auto_disable_users = eea.ldapadmin.users_admin:'
                        'auto_disable_users'
                     ]
                    },
      )
