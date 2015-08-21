# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import re
import os
import socket
import xml.etree.cElementTree as Et

from minion.plugins.base import ExternalProcessPlugin


class NMAPPlugin(ExternalProcessPlugin):
    PLUGIN_NAME = 'Nmap'
    PLUGIN_VERSION = '1.0'
    PLUGIN_WEIGHT = 'medium'

    NMAP_EXECUTABLE = 'nmap'

    DEFAULT_PORTS = {
        'TCP': ['21', '22', '80', '443']
    }
    DEFAULT_SCANTYPE = 'tcp_connect'
    DEFAULT_SEVERITY = 'medium'

    port_severity = []


    def do_configure(self, configuration=None, enable_logging=False):
        """Initialize the nmap plugin (aka __init__)"""

        # This is useful for testing, where a new instance can pass in a configuration object
        if configuration: self.configuration = configuration

        self.SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical']

        # 0 -> info, 1 -> low, etc.
        self.SEVERITY_MAPPING = {severity: self.SEVERITY_ORDER.index(severity) for severity in self.SEVERITY_ORDER}

        # Process the configuration, creating mappings of port -> severity and version -> severity
        self._create_port_to_severity_mappings()
        self._create_version_to_severity_mappings()

        # Variables to hold stdout and stderr
        self.stdout = self.stderr = ''

        # Set the default severities, for both ports and versions
        self.DEFAULT_SEVERITY = self.configuration.get('configuration', {}).get('default_severity', self.DEFAULT_SEVERITY)

        # Enable logging during development
        if enable_logging:
            import logging
            self.logger = logging.getLogger('minion-plugin-nmap')
            self.logger.setLevel(logging.DEBUG)

            fh = logging.FileHandler('/var/log/minion/nmap.log')
            self.logger.addHandler(fh)


    def _create_issue_unauthorized_open_port(self, severity, host, port, product):
        """Generate issues for open ports; they will have one of the three formats:

        192.168.0.1: open port (515)
        192.168.0.1: open port (443), running: Apache httpd (authorized software)
        192.168.0.1: open port (445), running: Samba smbd 3.X (unrecognized software)
        """

        sev = severity['severity']
        if sev == 'info':
            authorization = "authorized"
        else:
            authorization = "unauthorized"

        # Generate summaries of the issues
        if 'version' in severity['type']:
            # If software is unrecognized (not matching anything in a severity list), we should say so that instead
            if severity['recognized'] == False:
                authorization = "unrecognized"

            summary = '{host}: open port ({port}), running: {product} ({authorization} software)'.format(
                authorization=authorization, host=host, port=port, product=product)
        elif product:
            summary = '{host}: open port ({port}), running: {product}'.format(
                host=host, port=port, product=product)
        else:
            summary = '{host}: open port ({port})'.format(
                host=host, port=port)

        # Get the severity of the port
        issue = {
            'Severity': sev.capitalize(),
            'Summary': summary,
            'Description': summary,
            'URLs': [{'URL': '{host}:{port}'.format(host=host, port=port)}],
            'Ports': [port],
            'Classification': {
                'cwe_id': '200',
                'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
            }
        }

        return issue

    def _create_port_to_severity_mappings(self):
        """Generate the internal structure SEVERITY_TO_PORTS, which contains all the levels of severity, along with
        which ports are bound to that severity"""

        self.SEVERITY_TO_PORTS = {}

        for level in self.SEVERITY_ORDER:
            self.SEVERITY_TO_PORTS[level] = set()
            ports = self.configuration.get('severity', {}).get('ports', {}).get(level, [])
            for port in ports:
                port_range = self._generate_port_range(port)

                # A range like 6666-6669, or a single port
                if len(port_range) > 1:
                    self.SEVERITY_TO_PORTS[level].update(range(port_range[0], port_range[1] + 1))
                else:
                    self.SEVERITY_TO_PORTS[level].update([port_range[0]])


    def _create_version_to_severity_mappings(self):
        """Generate the internal struction SEVERITY_TO_VERSION, which contains all the levels of severity, along with
        which regular expressions are bound to that severity"""

        self.SEVERITY_TO_VERSION = {}

        for level in self.SEVERITY_ORDER:
            self.SEVERITY_TO_VERSION[level] = []
            for version in self.configuration.get('severity', {}).get('version', {}).get(level, []):
                self.SEVERITY_TO_VERSION[level].append(re.compile('^' + version, re.IGNORECASE))


    @staticmethod
    def _generate_port_range(port):
        """Generates an array to create a port range from as well as validate that the ports are valid

        Args:
            port: a string containing a port or port range

        Returns:
            an array containing either a single port or the bottom and top port of that range; for example either
            '21' -> [21, 21] or '6666-6668' -> [6666, 6668]"""

        # Make sure that every port is an integer, and within the proper range of 1-65535
        try:
            port = [int(x) for x in port.split('-')]
            if port[0] < 1 or port[-1] > 65535:
                raise ValueError
            return port
        except:
            raise Exception('Invalid port or port range in configuration: "{0}"'.format(port))


    def _generate_switches(self):
        """Based on the values set in the configuration -> scan section, generate all the switchs necessary to
        run nmap"""

        # We want XML output to stdout, with no stylesheet, and we want to skip host discovery
        switches = ['-oX', '-', '--no-stylesheet', '-Pn', '--open']

        # Mapping of all the friendly names to their nmap scan flags
        scan_type_mappings = {
            'christmas': 'X',
            'fin': 'F',
            'null': 'N',
            'syn': 'S',
            'tcp_connect': 'T',
            'udp': 'U',
            'version': 'V'
        }

        # TODO: check for incompatible flag combinations (low priority)

        # Compile all scan types into a single -s switch, like -sTUV
        scan_type_switch = '-s'
        for scan_type in self.configuration.get('scan', {}).get('types', [self.DEFAULT_SCANTYPE]):
            scan_type_switch += scan_type_mappings.get(scan_type, '')
        switches.append(scan_type_switch)

        # Either we want top ports, or we want to manually specify them
        top_ports = int(self.configuration.get('scan', {}).get('ports', {}).get('top_ports', 0))
        if (top_ports > 0):
            switches += ['--top-ports', str(top_ports)]
        else:
            ports = ''

            # Retrieve the settings from the configuration settings
            tcp = self.configuration.get('scan', {}).get('ports', {}).get('TCP', [])
            udp = self.configuration.get('scan', {}).get('ports', {}).get('UDP', [])

            # Use the default settings if no ports configuration object exists
            if not tcp and not udp:
                tcp = self.DEFAULT_PORTS['TCP']

            # Be lenient in case somebody accidentally` defines a port using an integer instead of a string
            stringify = lambda(x): [str(x) for x in x]  # now I just need to icecreamify
            tcp, udp = stringify(tcp), stringify(udp)

            # Validate every entry
            for entry in tcp + udp:
                self._generate_port_range(entry)

            if (tcp or udp):
                switches.append('-p')
            if tcp:
                ports += 'T:' + ','.join(tcp)

            # Only add UDP ports to the scan if UDP was actually specified in the scan type
            if udp and 'udp' in self.configuration.get('scan', {}).get('types', []):
                if ports: ports += ',U:' + ','.join(udp)
                else: ports = 'U:' + ','.join(udp)

            switches.append(ports)

        return switches


    def get_severity(self, port, product=None):
        """Given a port number and possible product version, return the severity associated with them.

        If both the port and product have a severity associated with it, the plugin will set the severity to the higher
        of the two, unless version_severity_override has been set in the plan.

        If an open port fails to match a value in severity -> port or in severity -> version, then return
        configuration -> default_severity.
        """

        result = {
            'severity': None,
            'type': []
        }

        # Call the severity functions, to get the severities for the passed in ports and products
        port_result = self.get_severity_for_port(port)
        version_result = self.get_severity_for_version(product)

        # Get the severity for both the port and the version
        port_sev = port_result['severity']
        version_sev = version_result['severity']

        # In the case of an item appearing in neither the port nor version list, we just return the internally set
        # default port severity
        if port_sev == None and version_sev == None:
            result['severity'] = self.DEFAULT_SEVERITY
            result['type'] = ['port']

        # There's a defined port severity, but no version severity
        elif port_sev != None and version_sev == None:
            result['severity'] = port_sev
            result['type'] = ['port']

        # There's a defined version severity, but no port severity
        elif port_sev == None and version_sev != None:
            result['severity'] = version_sev
            result['recognized'] = version_result['recognized'] # TODO switch to something more generic?
            result['type'] = ['version']

        # If there's both a port and version severity, we the higher severity of the two, unless we've set
        # the version_severity_override option, in which case we always return the version severity
        else:
            ver_override = self.configuration.get('configuration', {}).get('version_severity_override', False)

            if ver_override:
                result['severity'] = version_sev

            else:
                sev = max(self.SEVERITY_MAPPING[port_sev], self.SEVERITY_MAPPING[version_sev])
                result['severity'] = self.SEVERITY_ORDER[sev]

            result['recognized'] = version_result['recognized']
            result['type'] = ['port', 'version']


        return result


    def get_severity_for_port(self, port):
        """Given a particular port, return the severity of associated with that port. If it fails to match, severity
        will be set to None.

        Args:
            port: integer containing the open port number

        Returns:
            A dictionary containing the severity as well as all whether the product was recognized (ie, it matches
        an entry in severity -> version), or if it wasn't.  For example:

        {'severity': 'high',
         'recognized': False

        """

        result = {
            'severity': None,
        }

        port = int(port)
        for severity in self.SEVERITY_ORDER[::-1]:   # higher priorities take precedence, in case of multiple matches
            if port in self.SEVERITY_TO_PORTS[severity]:
                result['severity'] = severity
                return result

        return result


    def get_severity_for_version(self, product):
        """Given a particular version string (such as OpenSSL 6.2), return the severity of that version.  If the product
        is not recognized, and configuration -> raise_unrecognized_software is set, it will return the severity set in
        configuration -> raise_unrecognized_software_severity.  Otherwise, it will return with a severity of None.

        Args:
            product: The version string generated by nmap, which should consist of product name combined with its version

        Returns:
            A dictionary containing the severity as well as all whether the product was recognized (ie, it matches
        an entry in severity -> version), or if it wasn't.  For example:

        {'severity': 'high',
         'recognized': False}
        """

        result = {
            'severity': None,
            'recognized': False
        }

        if product == None:
            return result

        for severity in self.SEVERITY_ORDER[::-1]:   # higher priorities take precedence, in case of multiple matches
            for expression in self.SEVERITY_TO_VERSION[severity]:
                if expression.search(product) != None:
                    result['recognized'] = True
                    result['severity'] = severity

                    return result

        # If the user has set raise_unrecognized_software, we raise to a specified severity
        if self.configuration.get('configuration', {}).get('raise_unrecognized_software', False):
            result['recognized'] = False
            result['severity'] = self.configuration.get('configuration', {}).get(
                'raise_unrecognized_software_severity', self.DEFAULT_SEVERITY)

        return result


    def generate_issues(self, output):
        """Generates a list of issues based on the parsed nmap output generated by parse_nmap_xml()

        Args:
           output: the dictionary generated by parse_nmap_xml()

        Returns:
           an array of issues, generated from discovered open ports
        """
        issues = []

        # Sort the list of hosts by IP address; if that fails, then just sort alphabetically
        try:
            hosts = sorted(output.keys(), key=lambda host: socket.inet_aton(host))
        except socket.error:
            hosts = sorted(output.keys())

        # Look up for each host
        for host in hosts:
             for port in sorted(output[host]['ports'].keys(), key=int):
                 entry = output[host]['ports'][port]
                 if 'open' in entry['state']:
                     severity = self.get_severity(port, entry['product'])
                     issues.append(self._create_issue_unauthorized_open_port(severity, host, port, entry['product']))


        return issues


    @staticmethod
    def parse_nmap_xml(xml, baseline={}):
        """Parses the output of nmap -oX --no-stylesheet and returns a Python dictionary containing information on
        each host that was scanned.

        Args:
            xml: A string containing the entirety of the nmap output
            baseline: a JSON object that contains entries that, should they match, are removed from the parsed output

        Returns:
            A dictionary mapping nmap results on each host scanned.  For example:

            '10.0.1.1': {'hostnames': [],
              'ip': '10.0.1.1',
              'ports': {'22': {'name': 'ssh',
                               'product': 'OpenSSH',
                               'protocol': 'tcp',
                               'state': 'open',
                               'version': '6.2'}}},
            '10.0.1.4': {'hostnames': [],
              'ip': '10.0.1.4',
              'ports': {'22': {'name': 'ssh',
                               'product': 'OpenSSH',
                               'protocol': 'tcp',
                               'state': 'open',
                               'version': '6.2'},
                         '443': {'name': 'http',
                                 'product': 'Apache httpd',
                                 'protocol': 'tcp',
                                 'state': 'open',
                                 'version': None},
                         '8080': {'name': 'http',
                                 'product': 'XBMC Web Media Manager',
                                 'protocol': 'tcp',
                                 'state': 'open',
                                 'version': None}}}}

        Raises:
            Exception: If cElementTree is unable to parse the XML output.
        """

        hosts = {}

        try:
            root = Et.fromstring(xml)
        except:
            raise Exception("Unable to parse nmap output")

        # Get every host found
        for host in root.findall("host"):
            # Get the IP
            ip = host.find('address').get('addr')

            # Get the hostname if defined (user selected), otherwise use the IP address as the hostname
            hostname = ''
            hostnames = []
            for hn in host.find('hostnames'):
                if hn.get('type') == 'user':
                    hostname = hn.get('name')
                else:
                    hostnames.append(hn.get('name'))
            if not hostname:
                hostname = ip

            hosts[hostname] = {}
            hosts[hostname]['hostnames'] = hostnames
            hosts[hostname]['ip'] = ip
            hosts[hostname]['ports'] = {}

            # Get open ports, and stuff their data into our hosts data structure
            ports = host.find('ports')
            for port in ports.findall('port'):
                portid = port.get('portid')
                state = port.find('state').get('state')

                service = port.find('service')
                product = service.get('product')
                version = service.get('version')

                if product and version:
                    product = product + ' ' + version

                if 'open' in state:
                    hosts[hostname]['ports'][portid] = {
                        'protocol': port.get('protocol'),
                        'state': state,
                        'product': product,
                        'name': service.get('name'),
                    }


        # If a baseline has been passed in, we need to prune the output of all those entries
        if baseline:
            # "Deserialize" the baseline, where you can't use periods in key entries (hostnames)
            for baseline_host in baseline.iterkeys():
                baseline[ baseline_host.replace('_', '.') ] = baseline.pop(baseline_host)

            for baseline_host in baseline:
                for baseline_port_num, baseline_port in baseline[baseline_host].get('ports', {}).iteritems():
                    baseline_state = baseline_port.get('state', None)
                    baseline_product = str(baseline_port.get('product', ''))

                    parsed_port = hosts.get(baseline_host, {}).get('ports', {}).get(baseline_port_num, {})
                    parsed_state = parsed_port.get('state', None)
                    parsed_product = str(parsed_port.get('product', ''))

                    if baseline_state == None:
                        continue

                    if baseline_state == parsed_state and re.search('^' + baseline_product, parsed_product, re.IGNORECASE):
                        del(hosts[baseline_host]['ports'][baseline_port_num])

        return hosts


    def do_start(self):
        """Locates and launches the nmap executable"""

        # Locate nmap on the file system
        nmap_path = self.locate_program(self.NMAP_EXECUTABLE)
        if nmap_path is None:
            raise Exception("Unable to locate {0} in path".format(self.NMAP_EXECUTABLE))

        # Simplistic target parsing is all we need, as nmap can understand network ranges and
        # hostnames
        target = self.configuration['target'].split('//')[-1]

        # Launch nmap
        self.spawn(nmap_path, self._generate_switches() + [target])

    def do_process_stdout(self, data):
        self.stdout += data

    def do_process_stderr(self, data):
        self.stderr += data

    def do_process_ended(self, status):
        """Once the plugin has finished running, parse the nmap output, generate the issues, and end execution"""

        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            result = self.parse_nmap_xml(self.stdout,
                                         self.configuration.get('baseline', {}))
            issues = self.generate_issues(result)

            self.report_issues(issues)


            self.report_finish()
        else:
            failure = {
                "hostname": socket.gethostname(),
                "exception": self.stderr,
                "message": "Plugin failed"
            }
            self.report_finish("FAILED", failure)
