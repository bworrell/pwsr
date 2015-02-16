#!/usr/bin/env python

import sys
from os.path import (abspath, dirname, join)
from setuptools import (setup, find_packages)

BASE_DIR = dirname(abspath(__file__))
VERSION_FILE = join(BASE_DIR, 'pwsr', 'version.py')

def get_version():
    with open(VERSION_FILE) as f:
        for line in f.readlines():
            if line.startswith("__version__"):
                version = line.split()[-1].strip('"')
                return version
        raise AttributeError("Package does not have a __version__")


py_maj, py_minor = sys.version_info[:2]

if py_maj != 2:
    raise Exception('Python 2.7 required!')

if (py_maj, py_minor) < (2, 7):
    raise Exception('Python 2.7 required!')

fn_readme = join(BASE_DIR, "README.rst")
with open(fn_readme) as f:
    readme = f.read()

install_requires = [
    'google-api-python-client>=1.2',
    'pyperclip>=1.3',
    'python-mcrypt>=1.1'
]

for i in install_requires:
    print i

extras_require = {
    'docs': [
        'Sphinx==1.2.1',
        'sphinxcontrib-napoleon==0.2.4',
    ],
    'test': [
        "nose==1.3.0",
        "tox==1.6.1"
    ],
}

setup(
    name='pwsafe-remote',
    description='Password Safe Remote: Syncs PasswordSafe over Google Documents',
    author='Bryan Worrell',
    author_email='',
    url='https://github.com/bworrell',
    version=get_version(),
    packages=find_packages(),
    scripts=['pwsr/scripts/pwsr-get.py', 'pwsr/scripts/pwsr-search.py'],
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extras_require,
    long_description=readme,
    keywords="passwordsafe pwsafe password database"
)
