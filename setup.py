#!/usr/bin/env python3
"""A setuptools based setup module.

See:
    https://packaging.python.org/en/latest/distributing.html
    https://github.com/pypa/sampleproject
"""

# To use a consistent encoding
import os
from os import path
from multivault import __version__ as VERSION
# Always prefer setuptools over distutils
from setuptools import setup, find_packages

HERE = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(HERE, 'README.md'), encoding='utf-8') as f:
    LONG_DESCRIPTION = f.read()

setup(
    name='multivault',

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version='{}'.format(VERSION),

    description='A CLI to encrypt and decrypt content for ansible',
    long_description=LONG_DESCRIPTION,

    # The project's main homepage.
    url='https://github.com/Selfnet/multivault',

    # Author details
    author='Marcel Fest',
    author_email='marcelf@selfnet.de',

    # Choose your license
    license='MIT',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',
        'Topic :: Security :: Cryptography',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3 :: Only'
    ],

    # What does your project relate to?
    keywords='crypting ansible multivault vault cli gpg gnupg ldap',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(exclude=['bin', 'dists', 'lib', 'contrib', 'docs', 'tests']),

    # Alternatively, if you want to distribute just a my_module.py, uncomment
    # this:
    # py_modules=["Multivault"],

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['PyYAML', 'ldap3',
        'paramiko', 'requests', 'voluptuous', 'hkp4py'],
    
    # Dependencies which are not on pypi
    # dependency_links=[
    #     'git+https://github.com/Selfnet/hkp4py.git@master#egg=hkp4py'
    #     ],
    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    extras_require={
        'dev': ['pylint', 'autopep8', 'pep8'],
    },

    # Although 'package_data' is the preferred approach, in some case you may
    # need to place data files outside of your packages. See:
    # http://docs.python.org/3.4/distutils/setupscript.html#installing-additional-files # noqa
    # In this case, 'data_file' will be installed into '<sys.prefix>/my_data'
    # data_files=[('multivault-sample.yml')],
    data_files=[(os.path.join('/etc'),
                 ['multivault/multivault.yml'])],
    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    entry_points={
        'console_scripts': [
            'multivault=multivault.multivault:main',
        ],
    },
)
