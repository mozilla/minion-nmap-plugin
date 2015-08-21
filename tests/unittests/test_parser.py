# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os
import unittest
import minion.plugins.nmap

class TestParser(unittest.TestCase):
    def test_nmap_parsing(self):
        # Load up the nmap xml output
        nmapf = os.path.realpath(os.path.join(self.cwfd, '..', '..', 'etc', 'sample-nmap-output.xml'))
        with open(nmapf) as fp:
            self.nmap.stdout = fp.read()

        expected_result = {
            '192.168.0.0': {'hostnames': [], 'ip': '192.168.0.0', 'ports': {}},
            '192.168.0.1': {'hostnames': [],
                            'ip': '192.168.0.1',
                            'ports': {'22': {'name': 'ssh',
                                             'product': 'OpenSSH 6.2',
                                             'protocol': 'tcp',
                                             'state': 'open'},
                                      '548': {'name': 'afp',
                                              'product': None,
                                              'protocol': 'tcp',
                                              'state': 'open'},
                                      '88': {'name': 'kerberos-sec',
                                             'product': 'Heimdal Kerberos',
                                             'protocol': 'tcp',
                                             'state': 'open'}}},
            '192.168.0.2': {'hostnames': [],
                            'ip': '192.168.0.2',
                            'ports': {'3306': {'name': 'mysql',
                                               'product': 'MySQL 5.0.54',
                                               'protocol': 'tcp',
                                               'state': 'open'}}},
            '192.168.0.3': {'hostnames': [], 'ip': '192.168.0.3', 'ports': {}},
            '192.168.0.4': {'hostnames': [],
                            'ip': '192.168.0.4',
                            'ports': {'22': {'name': 'ssh',
                                             'product': 'OpenSSH 6.2',
                                             'protocol': 'tcp',
                                             'state': 'open'},
                                      '8080': {'name': 'http',
                                               'product': 'XBMC Web Media Manager',
                                               'protocol': 'tcp',
                                               'state': 'open'}}},
            '192.168.0.5': {'hostnames': [], 'ip': '192.168.0.5', 'ports': {}},
            '192.168.0.6': {'hostnames': [], 'ip': '192.168.0.6', 'ports': {}},
            '192.168.0.7': {'hostnames': [], 'ip': '192.168.0.7', 'ports': {}}}

        self.assertEquals(expected_result, self.nmap.parse_nmap_xml(self.nmap.stdout))

    def test_baseline_removal(self):
        # Load the sample nmap xml file (etc/sample-nmap-output.xml)
        nmapf = os.path.realpath(os.path.join(self.cwfd, '..', '..', 'etc', 'sample-nmap-output.xml'))
        with open(nmapf) as fp:
            self.nmap.stdout = fp.read()

        # Load the sample nmap baseline file (etc/sample-nmap-baseline.json)
        # In normal practice, this would be part of the plan
        baselinef = os.path.realpath(os.path.join(self.cwfd, '..', '..', 'etc', 'sample-nmap-baseline.json'))
        with open(baselinef) as fp:
            baseline = json.load(fp)

        expected_result = {
            '192.168.0.0': {'hostnames': [], 'ip': '192.168.0.0', 'ports': {}},
            '192.168.0.1': {'hostnames': [],
                            'ip': '192.168.0.1',
                            'ports': {'22': {'name': 'ssh',
                                             'product': 'OpenSSH 6.2',  # sample baseline has OpenSSH 3.14.15
                                             'protocol': 'tcp',
                                             'state': 'open'},
                                      '88': {'name': 'kerberos-sec',    # port missing from sample baseline
                                             'product': 'Heimdal Kerberos',
                                             'protocol': 'tcp',
                                             'state': 'open'}}},
            '192.168.0.2': {'hostnames': [],                            # host missing from sample baseline
                            'ip': '192.168.0.2',
                            'ports': {'3306': {'name': 'mysql',
                                               'product': 'MySQL 5.0.54',
                                               'protocol': 'tcp',
                                               'state': 'open'}}},
            '192.168.0.3': {'hostnames': [], 'ip': '192.168.0.3', 'ports': {}},
            '192.168.0.4': {'hostnames': [],
                            'ip': '192.168.0.4',
                            'ports': {'8080': {'name': 'http',
                                               'product': 'XBMC Web Media Manager',
                                               'protocol': 'tcp',
                                               'state': 'open'}}},
            '192.168.0.5': {'hostnames': [], 'ip': '192.168.0.5', 'ports': {}},
            '192.168.0.6': {'hostnames': [], 'ip': '192.168.0.6', 'ports': {}},
            '192.168.0.7': {'hostnames': [], 'ip': '192.168.0.7', 'ports': {}}}

        self.assertEquals(expected_result, self.nmap.parse_nmap_xml(self.nmap.stdout, baseline))

    def setUp(self):
        self.maxDiff = None

        # Load the configuration
        self.cwfd = os.path.dirname(os.path.realpath(__file__))

        jsonf = os.path.realpath(os.path.join(self.cwfd, '..', '..', 'etc', 'sample-plan.json'))
        with open(jsonf) as fp:
            self.nmap = minion.plugins.nmap.NMAPPlugin()
            self.nmap.do_configure(configuration=json.load(fp))

if __name__ == '__main__':
    unittest.main()
