from setuptools import find_packages, setup

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

          'beautifulsoup4',
          'lxml',

          # TODO: these need to be set as >=. Needs checks
          'deform>=2.0.8',
          'colander==1.7.0',
          'jellyfish==0.7.2; python_version>"3.0"',
          'jellyfish==0.2.0; python_version<"3.0"',
          'six',
          'xlrd>=1.2.0',
          'xlwt',
          'unidecode>1.0',

          'requests>2.0',
          'sparql-client',
          'python-dateutil',
          'py3dns; python_version>"3.0"',
          'pydns; python_version<"3.0"',
          'transliterate',
          'validate-email>=edw.1.3.1',
      ],
      entry_points={'console_scripts':
                    ['dump_ldap = eea.ldapadmin.ldapdump:dump_ldap',
                     'update_countries = '
                     'eea.ldapadmin.countries:update_countries',
                     'auto_disable_users = eea.ldapadmin.users_admin:' +
                     'auto_disable_users'
                     ]
                    },
      )
