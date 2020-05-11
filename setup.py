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
          download_url='https://github.com/mkorman90/regipy/releases/download/1.0.0/regipy-1.0.0.tar.gz',
          license="MIT",
          setup_requires=setup_requirements,
          install_requires=['construct==2.10.56',
                            'attrs==19.3.0',
                            'click==7.1.2',
                            'inflection==0.4.0',
                            'jsonlines==1.2.0',
                            'pytz==2020.1',
                            'logbook==1.5.3',
                            'tabulate==0.8.7',
                            'tqdm==4.46.0'],
          tests_require=test_requirements,
          extras_require={
              'test': test_requirements
          },
          include_package_data=True,
          keywords='Python, Python3, registry, windows registry, registry parser',
          classifiers=['Development Status :: 5 - Production/Stable',
                       'Intended Audience :: Developers',
                       'Natural Language :: English',
                       'License :: OSI Approved :: MIT License',
                       'Programming Language :: Python',
                       'Programming Language :: Python :: 3.7',
                       'Programming Language :: Python :: 3.8',
                       'Topic :: Software Development :: Libraries',
                       'Topic :: Utilities'],
          entry_points={
              'console_scripts': [
                  'registry-parse-header = regipy.cli:parse_header',
                  'registry-dump = regipy.cli:hive_to_json',
                  'registry-plugins-run = regipy.cli:run_plugins',
                  'registry-plugins-list = regipy.cli:list_plugins',
                  'registry-diff = regipy.cli:reg_diff',
                  'registry-transaction-logs = regipy.cli:parse_transaction_log'
              ]
          })


if __name__ == '__main__':
    main()
