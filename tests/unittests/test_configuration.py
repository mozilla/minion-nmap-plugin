# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os
import re
import unittest
import minion.plugins.nmap

# TODO tomorrow: add a configuration section, merge the severities sections

class TestConfiguration(unittest.TestCase):
    def test_switch_generation(self):
        # With the sample configuration, but adding in a UDP scan
        self.nmap.configuration['scan']['types'] = ['tcp_connect', 'udp', 'version']
        self.assertEquals(self.nmap._generate_switches(),
            ['-oX', '-', '--no-stylesheet', '-Pn', '--open', '-sTUV', '--top-ports', '250'])

        # Removing top_ports
        del(self.nmap.configuration['scan']['ports']['top_ports'])
        self.assertEquals(self.nmap._generate_switches(),
            ['-oX', '-', '--no-stylesheet', '-Pn', '--open', '-sTUV', '-p', 'T:20-22,25,53,80,113,143,443,465,587,993,995,3306,5462,6665-6667,6697,8080,U:53'])

        # What if we only had TCP ports?
        self.nmap.configuration['scan']['types'].remove('udp')
        del(self.nmap.configuration['scan']['ports']['UDP'])
        self.assertEquals(self.nmap._generate_switches(),
            ['-oX', '-', '--no-stylesheet', '-Pn', '--open', '-sTV', '-p', 'T:20-22,25,53,80,113,143,443,465,587,993,995,3306,5462,6665-6667,6697,8080'])

        # If we put an invalid port there, it should raise an exception
        self.nmap.configuration['scan']['ports']['TCP'].append(u'Mozilla is my Dinosaur')
        self.assertRaises(Exception, self.nmap._generate_switches)

        # Let's remove that last entry, and try it with a port that's too high
        self.nmap.configuration['scan']['ports']['TCP'].pop()
        self.nmap.configuration['scan']['ports']['TCP'].append(u'1000000')
        self.assertRaises(Exception, self.nmap._generate_switches)

        # Make sure that it doesn't barf it somebody uses an integer in the port listing
        self.nmap.configuration['scan']['ports']['TCP'] = [21, '22', 80, '443']
        self.assertEquals(self.nmap._generate_switches(),
            ['-oX', '-', '--no-stylesheet', '-Pn', '--open', '-sTV', '-p', 'T:21,22,80,443'])

        # If we have no entries at all, we should end up with the defaults
        del(self.nmap.configuration['scan']['ports'])
        self.assertEquals(self.nmap._generate_switches(),
            ['-oX', '-', '--no-stylesheet', '-Pn', '--open', '-sTV', '-p', 'T:21,22,80,443'])


    def test_port_to_severity_mappings(self):
        # Verify that it matches what we would expect, given the default configuration above
        expected_mapping = {
            'info': {22, 80, 443},
            'low': {53},
            'medium': {113, 143, 465, 587, 993, 6665, 6666, 6667, 6697, 8080},
            'high': {20, 21, 23},
            'critical': {3306, 5432}
        }
        self.assertEquals(self.nmap.SEVERITY_TO_PORTS, expected_mapping)

        # If we put an invalid port there, it should raise an exception
        self.nmap.configuration['severity']['ports']['medium'].append('Mozilla is my Dinosaur')
        self.assertRaises(Exception, self.nmap._create_port_to_severity_mappings)

        # Let's remove that last entry, and try it with a port that's too high
        self.nmap.configuration['severity']['ports']['medium'].pop()
        self.nmap.configuration['severity']['ports']['medium'].append(1000000)
        self.assertRaises(Exception, self.nmap._create_port_to_severity_mappings)


    def setUp(self):
        self.maxDiff = None

        # Load the configuration
        cwfd = os.path.dirname(os.path.realpath(__file__))
        jsonf = os.path.realpath(os.path.join(cwfd, '..', '..', 'etc', 'sample-plan.json'))
        with open(jsonf) as fp:
            self.nmap = minion.plugins.nmap.NMAPPlugin()
            self.nmap.do_configure(configuration=json.load(fp).get('configuration'))

if __name__ == '__main__':
    unittest.main()
