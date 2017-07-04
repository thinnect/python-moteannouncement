"""
moteannouncement: moteannouncement library.

Python application for receiving moteannouncements and sending queries.
"""

from setuptools import setup, find_packages
from os.path import join as pjoin

import moteannouncement

doclines = __doc__.split("\n")

setup(name="moteannouncement",
      version=moteannouncement.__version__,
      description="Python library for moteannouncement protocol",
      long_description="\n".join(doclines[2:]),
      url="http://github.com/thinnect/python-moteannouncement",
      author="Raido Pahtma",
      author_email="raido@thinnect.com",
      license="MIT",
      platforms=["any"],
      packages=find_packages(),
      install_requires=[
          "moteconnection", "simpledaemonlog", "serdepa", "pytz", "argconfparse", "six",
          "enum34"
      ],
      tests_require=["nose", "mock"],
      scripts=[pjoin("bin", "moteannouncements")],
      zip_safe=False)
