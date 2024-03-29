""" EEA LDAP Admin Installer
"""
from os.path import join
from setuptools import find_packages, setup

NAME = "eea.ldapadmin"
PATH = NAME.split('.') + ['version.txt']
VERSION = open(join(*PATH)).read().strip()

setup(name=NAME,
      version=VERSION,
      description="EEA LDAP Admin",
      long_description_content_type="text/x-rst",
      long_description=(
          open("README.rst").read() + "\n" +
          open(join("docs", "HISTORY.txt")).read()
      ),
      author='Eau de Web',
      author_email='office@eaudeweb.ro',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      url="https://github.com/eea/eea.ldapadmin",
      install_requires=[
          'eea.usersdb>=2.6',
          'naaya.ldapdump',
          'beautifulsoup4',
          'lxml',
          'deform>=2.0.8',
          'colander==1.7.0',
          'jellyfish==0.7.2; python_version>"3.0"',
          'jellyfish==0.2.0; python_version<"3.0"',
          'six',
          'xlrd>=1.2.0',
          'xlwt',
          'unidecode>1.0',
          'requests>2.0',
          'sparql-client>=3.9.dev0',
          'python-dateutil',
          'py3dns; python_version>"3.0"',
          'pydns; python_version<"3.0"',
          'transliterate',
          'plone.app.testing',
          'plone.app.robotframework',
      ],
      extras_require={
          'test': [
              'plone.app.testing',
              'plone.app.robotframework',
          ],
      },
      entry_points={'console_scripts':
                    ['dump_ldap = eea.ldapadmin.ldapdump:dump_ldap',
                     'update_countries = '
                     'eea.ldapadmin.countries:update_countries',
                     'auto_disable_users = eea.ldapadmin.users_admin:' +
                     'auto_disable_users'
                     ]
                    },
      )
