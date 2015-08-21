# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup

install_requires = [
    'netaddr>=0.7.11',
    'minion-backend'
]

scripts = ['scripts/minion-nmap-baseline']

setup(name='minion-nmap-plugin',
      version='1.0',
      description='Nmap Plugin for Minion',
      url='https://github.com/mozilla/minion-nmap-plugin/',
      author='April King',
      author_email='april@mozilla.com',
      packages=['minion', 'minion.plugins'],
      namespace_packages=['minion', 'minion.plugins'],
      zip_safe = True,
      include_package_data=True,
      install_requires = install_requires,
      scripts=scripts)
