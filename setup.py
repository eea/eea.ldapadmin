from setuptools import setup, find_packages

setup(name='eea.ldapadmin',
      version='1.4.19',
      author='Eau de Web',
      author_email='office@eaudeweb.ro',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'eea.usersdb>=1.3.6',
          'naaya.ldapdump',

          'BeautifulSoup',
          'lxml',

          'deform==0.9.9',
          'colander==1.0b1',
          'jellyfish==0.2.0',

          'xlrd>=0.9.3',
          'xlwt',
          'unidecode==0.04.13',

          'requests==1.2.3',
          'sparql-client',
      ],
      entry_points={'console_scripts':
                    ['dump_ldap = eea.ldapadmin.ldapdump:dump_ldap',
                     'update_countries = \
                        eea.ldapadmin.countries:update_countries',
                     ]
                    },
      )
