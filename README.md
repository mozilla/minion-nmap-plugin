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
      "version_whitelist": "Apache httpd,nginx",
      "addresses": [
        {
          "address": "127.0.0.1",
          "ports": [
            80,
            443
          ]
        }
      ]
    },
    "description": "",
    "plugin_name": "minion.plugins.nmap.NMAPPlugin"
  }
]
```
