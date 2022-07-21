#!/usr/bin/env python

import sys
import re
import glob
import os
from zlib import DEF_BUF_SIZE
import yaml
import csv
import ipaddress
import pickle
from tabulate import tabulate
from netmiko import ConnectHandler
from getpass import getpass
from pprint import pprint
from rich import print as rprint
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

# Gather show command outputs via Netmiko
def collectOutput(devices):
    for d in devices:
        # New file per device
        name = d.get('host')
        fo = open(f'output/{name}.txt', "w")
        # Connect to device
        ssh = ConnectHandler(**d)
        for line in config_commands:
            output = ssh.send_command(line)
            # Write outputs, per device
            fo.write(f'-------\n{line}-------\n')
            fo.write(output)


# Read in saved output files from specified directory
def readOutputs(directory):
    outputDict = dict()
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        # Check if it is a file
        if os.path.isfile(f):
            f = open(f, "r")
            str = f.read()
            str = str.strip()
            outputDict[filename] = str
            f.close()
    return outputDict


def getConfigList():
    #sourceDir = raw_input('Enter config file source dir: ')
    return glob.glob('/Users/craigb/Temp/*.log')
    sourceDir = sourceDir + "/*.log"
    return glob.glob(sourceDir)


def readHosts():
    f = open('hosts.yaml')
    hostDict = yaml.load(f)
    f.close()
    return hostDict


def printHosts(hosts):
    hostIPList = []
    for host in hosts:
        hostIPList.append([host.ip, host.username, host.password])
    printTable(hostIPList, ["IP", "Username", "Password"])


def runCommand(device, command):
    ssh = ConnectHandler(**device)
    return ssh.send_command(command)

### Wifi items

def checkSSIDs(o):
    x = re.findall('(Dot11Radio\d)\s+(.{4}\..{4}\..{4})\s+(Yes|No)\s+(\w*)', o)
    print(tabulate(x, headers=["Radio", "MAC", "Guest", "BSSID"]))


# FIXME
# Only grabbing first entry
def checkAssoc(o):
    x = re.findall('802.11 Client Stations on (Dot11Radio\d):\s+SSID\s\[(\w+)\]\s:\s+.*\s(.{4}\..{4}\..{4})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+::\s+(\w+)\s+\-+\s+\w+\s+(\w+)', o)
    print(tabulate(x, headers=["Radio", "SSID", "Station MAC", "Station IP", "Name", "State"]))


### Layer 2 items

# Check for VPC problems
def checkVPC(o):
    console.print("VPC")
    #x = re.search('vPC domain id\s+:\s+(\d+)', o)
    #if x: print(x.group(0))

    x = re.search('Peer status\s+:\s((?:\S|\s(?!\s))*)', o)
    if x and "ok" not in x.group(1): console.print(x.group(0), style="bold red")

    #x = re.search('Number of vPCs configured\s+:\s(.*)', o)
    #if x: print(x.group(0))

    x = re.search('Type-2 consistency status\s+:\s(.*)', o)
    if x and "success" not in x.group(1): console.print(x.group(0), style="bold red")

    x = re.search('Type-2 inconsistency reason\s+:\s(.*)', o)
    if x: console.print(x.group(0), style="bold red")


def checkVPCRole(o):
    x = re.search('(vPC role)\s+:\s+(\w+)', o)
    if x : console.print("VPC Role:", x.group(2), style="bold red")


# VLAN TCNs
def check_tcns(o, tcn_min):
    tcn_list = []
    x = re.findall('((VLAN\d{1,4}) is executing.*)([\s\w,.\-\(\)\/]+)(Number of topology changes (\d+).*)(occurred\s(.*)ago\n)(\s*from\s(.*))', o)
    for match in x:
        num_tcns = match[4].strip()
        if int(num_tcns) > tcn_min:
            tcn_list.append([match[1].strip(), num_tcns, match[6].strip(), match[8].strip()])

    tcn_list = sorted(tcn_list, key = lambda x: int(x[1]), reverse=True)
    if len(tcn_list) > 0:
        print(tabulate(tcn_list, headers=["VLAN ID", "# TCNs", "Last TCN Time", "Interface"]))
        print("\n")


# Old function
def getTCNs(**hosts):
    out = doInterrogate(host, "show spann detail")
    out = out.strip()
    vlans = []
    str = out.split("\n")
    for line in str:
        line = line.strip()
        if line.startswith("VLAN"):
            a = re.findall("^VLAN[0-9]+", line)
            a = a[0].strip()

        if line.startswith("Number of topology changes"):
            b = re.findall(" [0-9]+ ", line)
            b = b[0].strip()
            vlans.append([a, b])
    return vlans


## Layer 3 ##

def getVRFs(hosts):
    '''
    sh vrf
    VRF-Name                           VRF-ID State   Reason
    Admin                                   9 Up      --
    FAB                                     8 Up      --
    FAC                                     6 Up      --
    Labs                                   14 Up      --
    MASK                                    7 Up      --
    NECTAR                                  3 Up      --
    QSARR                                  13 Up      --
    SEC                                    10 Up      --
    SITECL                                  4 Up      --
    SITESRV                                 5 Up      --
    SITEUSGFSRV                            15 Up      --
    default                                 1 Up      --
    keepalive                              11 Up      --
    management                              2 Up      --
    '''


def checkIntIPs(o):
    '''
    sh ip int bri vrf all
    IP Interface Status for VRF "default"(1)
    Interface            IP Address      Interface Status
    Vlan501              10.40.252.8     protocol-up/link-up/admin-up
    Vlan511              10.40.15.28     protocol-up/link-up/admin-up
    '''


# Get Protocol Info
def checkProtocols(str):
    x = re.findall('Routing Protocol is .*', str)
    print(x)


# OSPF

def checkOSPFDetail(o):
    x = re.findall('Reference bandwidth unit is.*', o)
    print(x)

    x = re.findall('(Area BACKBONE)(\(.*\)\s+)Number of interfaces in this area is\s+(\d{1,})', o)
    print(tabulate(x, headers=["Area", "Area ID", "Num Interfaces"]))


def checkOSPFProcesses(o):
    x = re.findall('Routing Process (.*|\".*\S*.*\") with ID (\d+.\d+.\d+.\d+)(?:\sVRF)?(\s\w+)?', o)
    if x: print(tabulate(x, headers=["Process ID", "Area ID", "VRF"]))


def checkOSPFStuck(o):
    # Check for stuck in EXSTART
    x = re.findall('.*EXSTART\/.*', o)
    if len(x) > 0:
        rprint(f'[bold magenta]{f.name}[/bold magenta]')
        rprint(":vampire:", x, ":vampire:")


def checkOSPFMTU(o):
    mtu_ignore_list = []
    x = re.findall('(interface Vlan\d{1,4})([\s\w,.\-\(\)\/]+)mtu (\d{1,4})([\s\w,.\-\(\)\/]+)(ip ospf mtu-ignore)', o)
    if x:
        print(f'[bold magenta]{f.name}[/bold magenta]')
        for match in x:
            mtu_ignore_list.append( [match[0],match[2]] )
        print(tabulate(mtu_ignore_list, headers=["Interface", "MTU"]))
        print("\n")


def getCDPNeighbors(host):
    out = openSSH.doInterrogate(host, "show cdp neigh")
    out = out.strip()
    out = out.split("\n")
    print("Output:")
    print(out)
    print("\n")
    iterator = iter(out)
    for line in iterator:
        if line.startswith("Device ID") or line.startswith('Device-ID'):
            neighbor = next(iterator).strip()
            print(neighbor)


def getOrphanPorts(host):
    doInterrogate(host, "sh vpc orphan-ports")


def getHosts(fileList):
    hosts = []  # List of all hosts
    curHost = dict()    # Create empty dictionary for current host
    for file in fileList:   # Iterate on each file in the list
        curFile = openFile(file)    # Open the current file
        for line in curFile:    # Iterate on each line in current file
            line = line.strip()    # Chop of end of line
            curHost['filename'] = file
            if line.startswith('hostname'):
                curHost['hostname'] = line.split(' ')[1]
            if line.startswith('cisco'):    # FIXME - Not sufficient search
                curHost['platform'] = line.split(' ')[1]
            if line.startswith('Processor board ID'):   # FIXME - Not sufficient search
                curHost['serial'] = line.split(' ')[3]
        hosts.append(curHost.copy())
        curHost.clear()
    return hosts


def getPlatform(host):
    doInterrogate(host, "show ver")


def getSTPMode(out):
    curList = []
    stpModes = []
    for line in out.split("\n"):
        #print(line)
        if line.startswith('Switch is in'):
            curList.append(line.split(' ')[3])

        if re.search('Portfast Default', line) or re.search('Port Type Default .+ edge', line):
            curList.append(line.split(' ')[-1])

        if re.search('BPDU Guard Default', line):
            curList.append(line.split(' ')[-1])

        if line.startswith('Root bridge for'):
            curList.append(line.split(':')[-1])

        if re.search('Pathcost method used', line):
            curList.append(line.split(' ')[-1])

    out = filter(None, curList)
    return out


def printSTP(hosts):
    list = []
    for host in hosts:
        list.append(getSTPMode(host))
    print(list)
    printTable(list, ['Hostname', 'STP Mode', 'Root For', 'Portfast Default', 'BPDUGuard Default', 'Pathcost Method'])


def printTable(myList, headers=None):
    if headers:
        print(tabulate(myList, headers = headers, tablefmt="fancy_grid"))
    else:
        print(tabulate(myList, tablefmt="fancy_grid"))


def openFile(fname):
    try:
        fhand = open(fname)
        return fhand
    except:
        print('Unable to open file', fname)
        sys.exit(1)


def writeCSV(hosts):
    with open('mycsvfile.csv', 'wb') as f:  # Just use 'w' mode in 3.x
        fieldnames = hosts[1].keys()
        print(fieldnames)
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for host in hosts:
            w.writerow(host)


if __name__ == '__main__':

    directory = "/Users/craigb/Library/CloudStorage/OneDrive-CincinnatiBellTelephoneCompany,LLC/CBTS/Customers/Global Foundries/Data"
    #directory = "output"
    password = "test"
    #password = getpass()
    username = "craigb"

    f = open("sh_commands.txt", "r")
    config_commands = f.readlines()
    console = Console()

    # Run once to collect device outputs
    #collectOutput(devices)

    outputs = readOutputs(directory)
    for file, o in outputs.items():
        rprint(Panel(file))
        #check_tcns(o, 500)
        #checkVPC(o)
        checkVPCRole(o)
        #checkOSPFProcesses(o)
        #checkOSPFDetail(o)
        #checkAssoc(o)
