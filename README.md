Minion Nmap Plugin
==================

This is a plugin for [Minion](https://github.com/mozilla/minion) that executes the Nmap tool. It assumes `nmap` is installed on your system and that it is on the system PATH. If you use Ubuntu, Debian, Redhat or Fedora you can simply install the `nmap` package through `yum` or `apt-get`.

![Preview Image](http://i.imgur.com/n6ngwpk.png)

Installation
------------

You can install the plugin by running the following command in the minion-nmap-plugin repository:

```python setup.py install```

If running minion inside of vitualenv, make sure to activate it first.

Example of plan
---------------
```
{
  "configuration": {
    "baseline": {},
    "configuration": {
      "default_severity": "medium",
      "raise_unrecognized_software": false,
      "raise_unrecognized_software_severity": "high",
      "version_severity_override": false
    },
    "scan": {
      "types": ["tcp_connect", "version"],
      "ports": {
        "TCP": ["20-22", "25", "53", "80", "113", "143", "443", "465", "587", "993", "995", "3306", "5462", "6665-6667", "6697", "8080"],
        "UDP": ["53"],
        "top_ports": 250
      }
    },
    "severity": {
      "ports": {
        "info": ["22", "80", "443"],
        "low": ["53"],
        "medium": ["113", "143", "465", "587", "993", "993", "6665-6667", "6697", "8080"],
        "high": ["20-21", "23"],
        "critical": ["3306", "5432"]
      },
      "version": {
        "info": ["Apache httpd", "nginx", "OpenSSH"],
        "high": ["Apache httpd 1", "Apache httpd 2.0"],
        "critical": ["MySQL", "PostgreSQL"]
      }
    }
  },
  "description": "Run the Nmap scanner.",
  "plugin_name": "minion.plugins.nmap.NMAPPlugin"
}
```
Available configuration options
-------------------------------
Most of the options are not mandatory and some have default values.

* `baseline`: a JSON blob that tells the nmap plugin which services and ports that it already knows about, so as to not generate alerts
* `configuration`
  * `default_severity`: the severity of issue to raise if the plugin recognizes neither the port nor the version detected
  * `raise_unrecognized_software`: when set to true, any software that doesn't match an item in `severity -> version` will raise an issue with the severity of `raise_unrecognized_software_severity`. Ideally set to true, but set to false by default so as to not raise a lot of erroneously high issues on initial scans. Note that if this is not set, then any software that doesn't match a pattern in `severity -> version` will simply return the severity associated with that port, or `configuration -> default_severity` if it matches neither port nor version.
  * `raise_unrecognized_software_severity`: the severity of issue the plugin will raise when it detects software that isn't recognized
  * `version_severity_override`: on a typical issue, the plugin will return the highest severity associated with either the port or the value. In certain circumstances, people may want to run a known safe product on an unsafe port; setting this will cause the plugin to return the severity associated with that version of software, even if the port may normally generate a higher severity issue
* `scan`
  * `types`: options are `tcp_connect` (-sT), `udp` (-sU), `syn` (-sS), `null` (-sN), `fin` (-sF), `christmas` (-sX), and `version` (-sV)
  * `ports`: a list of TCP and UDP ports to tell nmap to scan, unless overridden by `scan` -> `top_ports`
  * `top_ports`: instructs nmap to scan the top X most commonly known ports; if set to 0 (or removed), nmap will instead scan the ports listed in `scan -> ports -> TCP/UDP`
* `severity`
  * `ports`: the severity of issue to raise, if nmap detects an open port; supports ranges of numbers such as 6665-6667
  * `version`: when doing a version scan, the severity of issue to raise if nmap detects a version of software matching a version listed: each entry is a regular expression, allowing complex subversion detection

Baselines
---------
Baselines can be generated by generating an XML file with an nmap scan, and then feeding its output into `minion-nmap-baseline`:

```
$ nmap -oX /tmp/nmap-output.xml --no-stylesheet --top-ports 100 -sTV 192.168.0.0/24
$ minion-nmap-baseline /tmp/nmap-output.xml
```

Each baseline file contains a JSON entry for every port found during the nmap scan.  It also includes an `__ALLHOSTS__` entry, which has two keys:

```
"__ALLHOSTS__": {
  "ports": ["80", "443"],
  "products": ["nginx"]
}
```

`ports` works like `severity -> ports` in the scan section: they can be individual ports, or port ranges (8080-8089)
`products` functions the same as in `severity -> version`: each entry is a regular expression, detailing a piece of software known to be safe in the network

`__ALLHOSTS__` lets you whitelist ports in an entire network range, for example, if you never want to be notified about port 22.  It also lets you whitelist known safe software, for example, OpenSSH 6.2.

Caveats
-------
Version scans for large numbers of ports on large network ranges can take a very long amount of time.

Also note that only tcp_connect and version scans will work with typical Minion permissions. For syn, null, fin, and christmas scans, please see [the nmap documentation](https://secwiki.org/w/Running_nmap_as_an_unprivileged_user) on how to configure your operating system to allow nmap to scan without root access.

TODO
----

* Add support for CIDR (network ranges) in the baseline
* Add support for artifact generation, particularly a baseline to download
* Better UDP support
