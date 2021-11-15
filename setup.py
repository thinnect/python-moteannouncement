"""
moteannouncement: moteannouncement library.

Python application for receiving moteannouncements and sending queries.
"""
from codecs import open
from os import path
from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

exec(open(path.join(here, 'moteannouncement/version.py')).read())

setup(name="moteannouncement",
      version=__version__,
      description="Python library for moteannouncement protocol",
      long_description=long_description,
      url="http://github.com/thinnect/python-moteannouncement",
      author="Raido Pahtma",
      author_email="raido@thinnect.com",
      license="MIT",
      platforms=["any"],
      packages=find_packages(),
      install_requires=[
          "moteconnection", "mistconnection", "serdepa", "pytz", "uptime"
      ],
      tests_require=["nose", "mock"],
      scripts=[path.join("bin", "moteannouncements")],
      zip_safe=False)
