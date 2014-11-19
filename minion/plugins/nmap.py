# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import re
import os
import collections
import netaddr
import uuid
import socket
from urlparse import urlparse
from minion.plugins.base import ExternalProcessPlugin

def _create_unauthorized_open_port_issue(ip, port, protocol):
    issue = {
        'Severity': 'High',
        'Summary': ip + ': ' + str(port) + '/' + str(protocol) + ' open (unauthorized)',
        'Description': 'Unauthorized open port for this host',
        'URLs': [{'URL': ip}],
        'Ports': [port],
        'Classification': {
            'cwe_id': '200',
            'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
        }
    }
    return issue


def _create_authorized_open_port_issue(ip, port, protocol):
    issue = {
        'Severity': 'Info',
        'Summary': ip + ': ' + str(port) + '/' + str(protocol) + ' open (authorized)',
        'Description': 'Authorized open port for this host',
        'URLs': [{'URL': ip}],
        'Ports': [port],
        'Classification': {
            'cwe_id': '200',
            'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
        }
    }
    return issue

def _create_wordy_version_issue(ip, service):
    issue = {
        'Severity': 'Low',
        'Summary': ip + ': ' + str(service['port']) + '/' + str(service['protocol']) + ' open: "' + service['version'] + '" (information disclosure)',
        'Description': 'Information disclosure',
        'URLs': [{'URL': ip}],
        'Ports': [service['port']],
        'Classification': {
            'cwe_id': '200',
            'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
        }
    }
    return issue


def _create_bad_filtration_firewall_issue(ip, closed_ports, filtered_ports):
    issue = {
        "Severity": "Medium",
        "Summary": ip + " - Probably misconfigured firewall",
        "Description": "The scan showed that both closed and filtered ports are present whereas they should be filtered"
                       "\n\n"
                       "Evidence --- Closed port(s) : " + closed_ports + " - Filtered port(s) : " + filtered_ports,
        "URLs": [{"URL": ip}],
        'Classification': {
            'cwe_id': '200',
            'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
        }
    }
    return issue


def _create_missing_filtration_firewall_issue(ip, closed_ports):
    issue = {
        "Severity": "Medium",
        "Summary": ip + " - Probably missing rules in firewall or no firewall at all",
        "Description": "The scan showed that only closed ports are present whereas they should be filtered"
                       "\n\n"
                       "Evidence --- Closed port(s) : " + closed_ports,
        "URLs": [{"URL": ip}],
        'Classification': {
            'cwe_id': '200',
            'cwe_url': 'http://cwe.mitre.org/data/definitions/200.html'
        }
    }
    return issue


def find_open_ports(ip_address, ip_addresses):
    for address in ip_addresses:
        if ip_address in address["address"]:
            return address["ports"]
    return []


def parse_nmap_output(output):
    ips = collections.OrderedDict()
    for line in output.split("\n"):

        match_ip = re.match('^Nmap\sscan\sreport\sfor\s(([0-9.]+)|\S+\s\(([0-9.]+)\))', line)
        if match_ip is not None:
            if match_ip.group(2) is not None:
                current_ip = match_ip.group(2)
            else:
                current_ip = match_ip.group(3)
            ips[current_ip] = []

        match_service = re.match('^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)', line)
        if match_service is not None:
            ips[current_ip].append({'port': int(match_service.group(1)), 'protocol': match_service.group(2),
                                    'state': match_service.group(3), 'service': match_service.group(4),
                                    'version': match_service.group(5)})

        match_not_show = re.match('^Not\sshown:\s\d+\s(closed|filtered)\sports', line)
        if match_not_show is not None:
            ips[current_ip].append({'not_shown': match_not_show.group(1)})

    return ips


def find_baseline_ports(ip, baseline):
    for info in baseline:
        if ip in info['address']:
            info_udp = info['udp'] if 'udp' in info else []
            info_tcp = info['tcp'] if 'tcp' in info else []
            return {'udp': info_udp, 'tcp': info_tcp}
    return {'udp': [], 'tcp': []}


def _validate_ports(ports):
    # 53,111,137,T:21-25,139,8080
    return re.match(r"(((U|T):)\d+(-\d+)?)(,((U|T):)?\d+(-\d+)?)*", ports)


def _validate_open_ports(open_ports):
    # 80,21-25,8080
    return re.match(r"(\d+(-\d+)?)(,(\d+)(-\d+)?)*", open_ports)


class NMAPPlugin(ExternalProcessPlugin):
    PLUGIN_NAME = "NMAP"
    PLUGIN_VERSION = "0.2"
    PLUGIN_WEIGHT = "light"

    NMAP_NAME = "nmap"

    def _load_whitelist(self, conf_path):

        if not os.path.isfile(conf_path):
            raise Exception("The given path doesn't lead to a file")

        try:
            with open(conf_path) as f:
                whitelist = f.readlines()
            return whitelist
        except Exception as e:
            raise Exception("Can't open the file for the given path")

    def ips_to_issues(self, ips):

        issues = []

        for ip in ips:
            closed_ports = ""
            filtered_ports = ""
            baseline_ports = find_baseline_ports(ip, self.baseline)

            for service in ips[ip]:
                if 'not_shown' in service:
                    if service["not_shown"] == "closed":
                        if not closed_ports:
                            closed_ports += "\"Not shown closed ports\""
                        else:
                            closed_ports += ", \"Not shown closed ports\""

                    if service["not_shown"] == "filtered":
                        if not filtered_ports:
                            filtered_ports += "\"Not shown filtered ports\""
                        else:
                            filtered_ports += ", \"Not shown filtered ports\""

                else:
                    if service['state'] == 'open' and service['port'] not in baseline_ports[service['protocol']]:
                        issues.append(_create_unauthorized_open_port_issue(ip, service['port'], service['protocol']))

                    if service['state'] == 'open' and service['port'] in baseline_ports[service['protocol']]:
                        issues.append(_create_authorized_open_port_issue(ip, service['port'], service['protocol']))

                    if service['state'] == 'closed':
                        if not closed_ports:
                            closed_ports += str(service['port'])
                        else:
                            closed_ports += ", " + str(service['port'])

                    if service['state'] == 'filtered':
                        if not filtered_ports:
                            filtered_ports += str(service['port'])
                        else:
                            filtered_ports += ", " + str(service['port'])

                    if service['version'] and service['version'].lower() not in self.version_whitelist:
                        issues.append(_create_wordy_version_issue(ip, service))

            if closed_ports and filtered_ports:
                issues.append(_create_bad_filtration_firewall_issue(ip, closed_ports, filtered_ports))
            elif closed_ports:
                issues.append(_create_missing_filtration_firewall_issue(ip, closed_ports))

        return issues

    def do_start(self):

        nmap_path = self.locate_program(self.NMAP_NAME)
        if nmap_path is None:
            raise Exception("Cannot find nmap in path")

        self.nmap_stdout = ""
        self.nmap_stderr = ""

        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']
        else:
            self.report_dir = os.path.dirname(os.path.realpath(__file__)) + "/artifacts/"

        self.baseline = []
        if 'baseline' in self.configuration:
            self.baseline = self.configuration.get('baseline')

        self.version_whitelist = []
        if 'version_whitelist' in self.configuration:
            self.version_whitelist = [v.lower() for v in self.configuration['version_whitelist']]

        try:
            target = netaddr.IPNetwork(self.configuration['target'])
        except:
            try:
                url = urlparse(self.configuration['target'])
                target = url.hostname
            except:
                raise Exception("Input target is not an IP address or a network of IP addresses or a valid URL")

        ### Check if parameters are specified (syntax "Parm1 Parm2 etc"
        params = []
        if 'parameters' in self.configuration:
            params = self.configuration.get('parameters')

            ### Put parameters into array
            params = params.split()
        else:
            ### Use default parameters
            params = ["-sV", "-sT", "-sU", "-Pn", "-PS21,22,80,443", "-PE"]
        args = [nmap_path]
        args += params

        ports = self.configuration.get('ports')
        if ports:
            if not _validate_ports(ports):
                raise Exception("Invalid ports specification")
            args += ["-p", ports]

        interface = self.configuration.get('interface')
        if interface:
            args += ["-e", interface]

        self.output_id = str(uuid.uuid4())
        self.xml_output = self.report_dir + "XMLOUTPUT_" + self.output_id + ".xml"

        args += ["-oX", self.xml_output, "--no-stylesheet"]

        args += [str(target)]

        self.spawn('/usr/bin/sudo', args)

    def do_process_stdout(self, data):
        self.nmap_stdout += data

    def do_process_stderr(self, data):
        self.nmap_stderr += data

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            ips = parse_nmap_output(self.nmap_stdout)
            issues = self.ips_to_issues(ips)

            self.report_issues(issues)

            self._save_artifacts()

            self.report_finish()
        else:
            self._save_artifacts()
            failure = {
                "hostname": socket.gethostname(),
                "exception": self.nmap_stderr,
                "message": "Plugin failed"
            }
            self.report_finish("FAILED", failure)

    def _save_artifacts(self):
        stdout_log = self.report_dir + "STDOUT_" + self.output_id + ".txt"
        stderr_log = self.report_dir + "STDERR_" + self.output_id + ".txt"
        output_artifacts = []

        if self.nmap_stdout:
            with open(stdout_log, 'w+') as f:
                f.write(self.nmap_stdout)
            output_artifacts.append(stdout_log)
        if self.nmap_stderr:
            with open(stderr_log, 'w+') as f:
                f.write(self.nmap_stderr)
            output_artifacts.append(stderr_log)

        if output_artifacts:
            self.report_artifacts("NMAP Output", output_artifacts)
        if os.path.isfile(self.xml_output):
            self.report_artifacts("NMAP XML Report", [self.xml_output])