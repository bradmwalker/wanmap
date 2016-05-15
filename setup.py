import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()
with open(os.path.join(here, 'CHANGES.md')) as f:
    CHANGES = f.read()

requires = [
    'arrow',
    'celery',
    'psycopg2',
    'pyramid_jinja2',
    'pyramid_tm',
    'waitress',
    'zope.sqlalchemy',
    ]

setup(name='wanmap',
      version='0.0',
      description='A distributed nmap web application',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
          "Programming Language :: Python",
          "Framework :: Pyramid",
          "Topic :: Internet :: WWW/HTTP",
          "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
      ],
      author='Brad Walker',
      author_email='brad@bradmwalker.com',
      url='https://wanmap.org',
      keywords='web pyramid pylons',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="wanmap",
      entry_points="""\
      [paste.app_factory]
      main = wanmap:main
      [console_scripts]
      initialize_wanmap_db = wanmap.scripts.initializedb:main
      """,
      )
