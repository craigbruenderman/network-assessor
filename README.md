# network-assessor

This is my feeble attempt at automating a lot of the typical L2 / L3 discovery I do on Cisco networks. I continually find a lot of the same vPC, STP and routing problems, but it's very tedious to analyze this across a large number of devices.

## Installation

pip install

## Development Notes

* Developed against
	* MacOS 12.3.1
	* Python 3.10.3

## Wish List

* Docker / Vagrant environment runtime
* PDF report generation
* Platform Support
	* IOS, IOS-XE, NX-OS
	* VOSS
	* EXOS
	* ASA
	* EOS
* Manually defined inventory
* Auto generated inventory from CSV
* Dynamic inventory from Netbox
* Runtime options to run against a directory of .log files, or interactively using SSH against a YAML file
