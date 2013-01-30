# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import re
import urlparse
from minion.plugin_api import ExternalProcessPlugin

NOTABLE_ISSUES = [
    {
        "_ports": [22],
        "Severity": "Low",
        "Summary": "Public SSH service found"
    },
    {
        "_ports": [53],
        "Severity": "Low",
        "Summary": "Public DNS service found"
    },
    {
        "_ports": [80,443],
        "Severity": "Informational",
        "Summary": "Standard HTTP services were found"
    },
    {
        "_ports": [3306],
        "Ports": [],
        "Severity": "High",
        "Summary": "Public MySQL database found",
        "Description": "A publicly accessible instance of the MySQL database was found on port 3306.",
        "Solution": "Configure MySQL to listen only on localhost. If other servers need to access to this database then use firewall rules to only allow those servers to connect."
    },
    {
        "_ports": [5432],
        "Severity": "High",
        "Summary": "Public PostgreSQL database found",
        "Description": "A publicly accessible instance of the PostgreSQL database was found on port 5432.",
        "Solution": "Configure PostgreSQL to listen only on localhost. If other servers need to access this database then use firewall rules to only allow those servers to connect."
    },
    {
        "_ports": [25,113,143,465,587,993,995],
        "Severity": "Medium",
        "Summary": "Email service(s) found",
        "Solution": "It is not recomended to run email services on the same server on which a web site is hosted. It is generally a good idea to separate services to different servers to minimize the attack surface."
    }
]

def find_notable_issue(port):
    for issue in NOTABLE_ISSUES:
        if port in issue['_ports']:
            return issue

def parse_nmap_output(output):
    services = []
    for line in output.split("\n"):
        match = re.match('^(\d+)/(tcp|udp)\s+open\s+(\w+)', line)
        if match is not None:
            services.append({'port':int(match.group(1)),'protocol':match.group(2), 'service':match.group(3)})
    return services

def find_port_in_issues(port, issues):
    for issue in issues:
        if port in issue['Ports']:
            return True

def find_earlier_found_issue(port, issues):
    for issue in issues:
        if port in issue['_ports']:
            return issue

def services_to_issues(services):

    unique_ports = set()
    for service in services:
        unique_ports.add(service['port'])
    
    high_risk_ports = set()

    issues = []

    for port in unique_ports:
        # If we have not seen this port before
        if port not in high_risk_ports and not find_port_in_issues(port, issues):
            issue = find_earlier_found_issue(port, issues)
            if issue:
                issue.setdefault("Ports", []).append(port)                
            else:
                issue = find_notable_issue(port)
                if issue:
                    # If we have a detailed issue then we use that
                    issues.append(issue)
                    issue.setdefault("Ports", []).append(port)
                else:
                    # Otherwise all unknown services go to high risk.
                    high_risk_ports.add(port)

    if len(high_risk_ports) > 0:
        issues.append({"Ports": list(high_risk_ports), "Severity": "High",
                       "Summary": "Unknown public services found."})
        
    for issue in issues:
        if '_ports' in issue:
            del issue['_ports']

    return issues

class NMAPPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "NMAP"
    PLUGIN_VERSION = "0.1"

    NMAP_NAME = "nmap"

    def _validate_ports(self, ports):
        # U:53,111,137,T:21-25,139,8080
        return re.match(r"(((U|T):)\d+(-\d+)?)(,((U|T):)?\d+(-\d+)?)*", ports)

    def do_start(self):
        nmap_path = self.locate_program(self.NMAP_NAME)
        if nmap_path is None:
            raise Exception("Cannot find nmap in path")
        self.nmap_stdout = ""
        self.nmap_stderr = ""
        u = urlparse.urlparse(self.configuration['target'])
        args = ["--open"]
        ports = self.configuration.get('ports')
        if ports:
            if not self._validate_ports(ports):
                raise Exception("Invalid ports specification")
            args += ["-p", ports]
        args += [u.hostname]
        self.spawn(nmap_path, args)

    def do_process_stdout(self, data):
        self.nmap_stdout += data

    def do_process_stderr(self, data):
        self.nmap_stderr += data

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            with open("nmap.stdout.txt", "w") as f:
                f.write(self.nmap_stdout)
            with open("nmap.stderr.txt", "w") as f:
                f.write(self.nmap_stderr)
            self.report_artifacts("NMAP Output", ["nmap.stdout.txt", "nmap.stderr.txt"])
            services = parse_nmap_output(self.nmap_stdout)
            issues = services_to_issues(services)
            self.callbacks.report_issues(issues)
            self.callbacks.report_finish()
        else:
            self.report_finish("FAILED")
