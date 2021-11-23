from setuptools import setup, find_packages

setup(name='eea.ldapadmin',
      version='1.0.4-ispra',
      author='Eau de Web',
      author_email='office@eaudeweb.ro',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=['eea.usersdb>=1.1.0', 'lxml', 'BeautifulSoup',
                        'deform', 'colander'],
)
