# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os
import unittest
import minion.plugins.nmap

# TODO tomorrow: add a configuration section, merge the severities sections

class TestSeverity(unittest.TestCase):
    NMAP_OUTPUT = """

    """

    def test_port_severity(self):
        # Individual ports
        self.assertEquals(self.nmap.get_severity_for_port(80), {'severity': 'info'})
        self.assertEquals(self.nmap.get_severity_for_port(53), {'severity': 'low'})
        self.assertEquals(self.nmap.get_severity_for_port(3306), {'severity': 'critical'})

        # These are in port ranges
        self.assertEquals(self.nmap.get_severity_for_port(6666), {'severity': 'medium'})
        self.assertEquals(self.nmap.get_severity_for_port(21), {'severity': 'high'})

        # If it's not in the list, should return None
        self.assertEquals(self.nmap.get_severity_for_port(45678), {'severity': None})


    def test_severity(self):
        # Anything on port 80 is simply info
        self.assertEquals(self.nmap.get_severity(80), {'severity': 'info', 'type': ['port']})

        # But if it's an outdated piece of software, it should show up as a higher severity, even on a low severity port
        self.assertEquals(self.nmap.get_severity(80, 'Apache httpd 2.0.17'), {'severity': 'high', 'type': ['port', 'version'], 'recognized': True})

        # If raise_unrecognized_software is not set, raise the default level of that port/software combination
        self.assertEquals(self.nmap.get_severity(80, 'Minion 24.7.3'), {'severity': 'info', 'type': ['port']})

        # The same, but an unrecognized port and unrecognized software, raising default_severity
        self.assertEquals(self.nmap.get_severity(45678, 'Minion 24.7.3'), {'severity': 'medium', 'type': ['port']})

        # If it's not in the list, and raise_unrecognized_software is true, raise the level
        # of raise_unrecognized_software_severity
        self.nmap.configuration['configuration']['raise_unrecognized_software'] = True
        self.assertEquals(self.nmap.get_severity(80, 'Minion 24.7.3'), {'severity': 'high', 'type': ['port', 'version'], 'recognized': False})

        # By default, we simply use the higher severity of either port or version; in some edge cases, people might want
        # to run safe software on "unsafe" ports (say, 3306), in which case we allow them to let version severity
        # override port severity
        self.nmap.configuration['configuration']['version_severity_override'] = True
        self.assertEquals(self.nmap.get_severity(3306, 'Apache httpd 2.4.20'), {'severity': 'info', 'type': ['port', 'version'], 'recognized': True})


    def test_version_severity(self):
        # Simple matches
        self.assertEquals(self.nmap.get_severity_for_version('nginx'), {'severity': 'info', 'recognized': True})
        self.assertEquals(self.nmap.get_severity_for_version('Apache httpd 2.16'), {'severity': 'info', 'recognized': True})
        self.assertEquals(self.nmap.get_severity_for_version('MySQL 5.7.8'), {'severity': 'critical', 'recognized': True})

        # Note that this matches *both* info and high: it should return high
        self.assertEquals(self.nmap.get_severity_for_version('Apache httpd 2.0.17'), {'severity': 'high', 'recognized': True})

        # If it's not set, then there should be no severity at all
        self.assertEquals(self.nmap.get_severity_for_version('Minion 24.7.3'), {'severity': None, 'recognized': False})

        # If it's not in the list, and raise_unrecognized_software is true, raise the level
        # of raise_unrecognized_software_severity
        self.nmap.configuration['configuration']['raise_unrecognized_software'] = True
        self.assertEquals(self.nmap.get_severity_for_version('Minion 24.7.3'), {'severity': 'high', 'recognized': False})


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
