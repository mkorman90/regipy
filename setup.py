#!/usr/bin/env python
import os
import re
import sys
from setuptools import setup, find_packages

# Requirements.
setup_requirements = ['pytest-runner'] if {'pytest', 'test', 'ptr'}.intersection(sys.argv) else []
test_requirements = ['pytest', 'pytest-flake8']

# Fetch readme content.
with open('docs/README.rst', 'r') as readme_file:
    readme = readme_file.read()


def _find_version(file_path):
    version_file = open(file_path, 'r').read()
    version_match = re.search(r'^__version__ = [\'"]([^\'"]*)[\'"]', version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError('Unable to find version string.')


def main():
    setup(name='regipy',
          packages=find_packages(),
          version=_find_version(os.path.abspath(os.path.join('regipy', '__init__.py'))),
          description='Python Registry Parser',
          long_description=readme,
          author='Martin G. Korman',
          author_email='martin@centauri.co.il',
          url='https://github.com/mkorman90/regipy/',
          license="MIT",
          setup_requires=setup_requirements,
          install_requires=['construct>=2.10',
                            'attrs>=21',
                            'inflection~=0.5.1',
                            'pytz',
                            'libfwsi-python==20220123'],
          tests_require=test_requirements,
          extras_require={
              'test': test_requirements,
              'cli': [
                  'click>=7.0.0',
                  'tabulate',
              ],
          },
          include_package_data=True,
          keywords='Python, Python3, registry, windows registry, registry parser',
          classifiers=['Development Status :: 5 - Production/Stable',
                       'Intended Audience :: Developers',
                       'Natural Language :: English',
                       'License :: OSI Approved :: MIT License',
                       'Programming Language :: Python',
                       'Programming Language :: Python :: 3.6',
                       'Programming Language :: Python :: 3.7',
                       'Programming Language :: Python :: 3.8',
                       'Programming Language :: Python :: 3.9',
                       'Topic :: Software Development :: Libraries',
                       'Topic :: Utilities'],
          entry_points={
              'console_scripts': [
                  'registry-parse-header = regipy.cli:parse_header',
                  'registry-dump = regipy.cli:registry_dump',
                  'registry-plugins-run = regipy.cli:run_plugins',
                  'registry-plugins-list = regipy.cli:list_plugins',
                  'registry-diff = regipy.cli:reg_diff',
                  'registry-transaction-logs = regipy.cli:parse_transaction_log'
              ]
          })


if __name__ == '__main__':
    main()
