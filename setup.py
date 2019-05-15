"""
moteannouncement: moteannouncement library.

Python application for receiving moteannouncements and sending queries.
"""

from setuptools import setup, find_packages
from os.path import join as pjoin

doclines = __doc__.split("\n")

setup(name="moteannouncement",
      version="0.4.1.dev1",
      description="Python library for moteannouncement protocol",
      long_description="\n".join(doclines[2:]),
      url="http://github.com/thinnect/python-moteannouncement",
      author="Raido Pahtma",
      author_email="raido@thinnect.com",
      license="MIT",
      platforms=["any"],
      packages=find_packages(),
      install_requires=[
          "moteconnection", "serdepa", "pytz", "six", "enum34", "uptime"
      ],
      tests_require=["nose", "mock"],
      scripts=[pjoin("bin", "moteannouncements")],
      zip_safe=False)
