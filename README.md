Minion NMAP Plugin
===================

[![Build Status](https://drone.io/github.com/Wawki/minion-nmap-plugin/status.png)](https://drone.io/github.com/Wawki/minion-nmap-plugin/latest)

This is a plugin for Minion that executes the NMAP tool. It assumes NMAP is installed on your system and that is is on the system PATH. If you use Ubuntu, Debian, Redhat or Fedora you can simply install the `nmap` package through `yum` or `apt-get`.

Installation
------------

You can install the plugin by running the following command in the minion-nmap-plugin repository:

```python setup.py install```

Example of plan
---------------

```
[
  {
    "configuration": {
      "version_whitelist": ["Apache httpd","nginx"],
      "addresses": [
        {
          "address": "127.0.0.1",
          "udp": ["53"],"tcp": ["80","443"]
        },
	{
          "address": "127.0.0.0/24",
          "udp": ["53"],"tcp": ["80","443","8080"]
        },
	{
          "address": "default",
          "udp": ["53"],"tcp": ["80"]
        }
      ],
      "severity": [
        {
          "default": "High",
          "Medium": [
            "25/tcp",
            "53/tcp",
            "53/udp"
          ],
          "Low": [
            "80/tcp",
            "443/tcp"
          ]
        }
      ],
      "ports": "T:22,80,U:53" 
    },

    "description": "",
    "plugin_name": "minion.plugins.nmap.NMAPPlugin"
  }
]
```
Available configuration option
------------------------------
Most of the options are not mandatory and some have default values.
* ```report_dir``` : directory where output and reports will be saved. By default, the path used is ```{nmap-plugin-folder}/artifacts```
* ```baseline ``` : array of dictionaries containing for each IP address authorized open ports. Specific IP must be ordered before CIDR range containing the IP. Else a default baseline can be specified. It can also be a path leading to a JSON file with the baseline.
* ```version_whitelist``` : array containing accepted version of services when the open port leak the name.
* ```severity``` : for each severity an array of ports is defined, and a default severity for the remaining.
* ```parameters``` : parameters to apply to Nmap when it is called. 
* ```ports``` : ports to scan, use the same syntax than Nmap
* ```baseline_port``` : flag to add every baseline port to the scan 
* ```interface``` : same as nmap option
* ```noPortIssue``` : flag to not raise an issue when an openport is found
