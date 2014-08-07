from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
  long_description = f.read()


setup(
  name="PyJOAT",
  version="1.0.0",
  author="R. Kevin Nelson",
  author_email="kevin@rkn.la",
  description="JWT OAuth 2.0 Access Token management",
  license="MIT",
  keywords="joat jwt json web access token oauth",
  url="https://github.com/rknLA/joat",
  packages=['joat'],
  long_description=long_description,
  install_requires=['PyJWT'],
  classifiers=[
    "Environment :: Web Environment",
    "Intended Audience :: Developers",
    "Development Status :: 3 - Alpha",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 2.7",
    "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    "Topic :: Software Development :: Libraries :: Python Modules"
  ]
)
