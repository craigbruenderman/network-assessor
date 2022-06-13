#!/usr/bin/env python

import sys
import re
import glob
import os
import yaml
import csv
import ipaddress
import pickle
from tabulate import tabulate
from netmiko import ConnectHandler
from getpass import getpass
from pprint import pprint
from rich import print


# Get Protocol Info
def getProtocols(str):
    x = re.findall('Routing Protocol is .*', str)
    print(x)

# OSPF Problems
def check_ospf(str):
    # Check for stuck in EXSTART
    x = re.findall('.*EXSTART\/.*', str)
    if len(x) > 0:
        print(f'[bold magenta]{f.name}[/bold magenta]')
        print(":vampire:", x, ":vampire:")

    mtu_ignore_list = []
    pat = re.compile('(interface Vlan\d{1,4})([\s\w,.\-\(\)\/]+)mtu (\d{1,4})([\s\w,.\-\(\)\/]+)(ip ospf mtu-ignore)')
    x = re.findall(pat, str)
    if x:
        print(f'[bold magenta]{f.name}[/bold magenta]')
        for match in x:
            mtu_ignore_list.append( [match[0],match[2]] )
        print(tabulate(mtu_ignore_list, headers=["Interface", "MTU"]))
        print("\n")
            

# VLAN TCNs
def check_tcns(str, tcn_min):
    tcn_list = []
    pat = re.compile('((VLAN\d{1,4}) is executing.*)([\s\w,.\-\(\)\/]+)(Number of topology changes (\d+).*)(occurred\s(.*)ago\n)(\s*from\s(.*))')
    x = re.findall(pat, str)
    for match in x:
        num_tcns = match[4].strip()
        if int(num_tcns) > tcn_min:
            tcn_list.append([match[1].strip(), num_tcns, match[6].strip(), match[8].strip()])
    
    tcn_list = sorted(tcn_list, key = lambda x: int(x[1]), reverse=True)
    if len(tcn_list) > 0:
        print(tabulate(tcn_list, headers=["VLAN ID", "# TCNs", "Last TCN Time", "Interface"]))
        print("\n")


def readOutputs(directory):
    outputList = []
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        # Check if it is a file
        if os.path.isfile(f):
            f = open(f, "r")
            str = f.read()
            str = str.strip()
            outputList.append(str)
            f.close()
    return outputList


def readHosts():
    f = open('hosts.yaml')
    hostDict = yaml.load(f)
    f.close()
    return hostDict


def runCommand(device, command):
    ssh = ConnectHandler(**device)
    return ssh.send_command(command)


def printHosts(hosts):
    hostIPList = []
    for host in hosts:
        hostIPList.append([host.ip, host.username, host.password])
    printTable(hostIPList, ["IP", "Username", "Password"])


def getHostNames(hosts):
    for host in hosts:
        openSSH.doInterrogate(host, "show hostname")


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


def getVRFs(host):
    out = openSSH.doInterrogate(host, "show vrf detail")
    out = out.strip()
    out = out.split("\n")
    vrfs = []
    for line in out:    # Iterate on each line in current file
        line = line.strip()    # Chop of end of line
        if line.startswith('VRF') or line.startswith('VRF-Name:'):
            line = line.split(' ')
            line = line[:2]
            if line[1] != "label":
                vrfs.append(line[1].translate(None, ","))
    return vrfs


def getVPC(host):
    print(openSSH.doInterrogate(host, "show vpc"))


def getVPCRole(host):
    doInterrogate(host, "show vpc role")


def getOrphanPorts(host):
    doInterrogate(host, "sh vpc orphan-ports")


def getVPCConsistency(host):
    doInterrogate(host, "sh vpc consistency-parameters global")


def getPortChannels(host):
    pass


def getIntIPs(host):
    doInterrogate(host, "show ip int bri")


def getConfigList():
    #sourceDir = raw_input('Enter config file source dir: ')
    return glob.glob('/Users/craigb/Temp/*.log')
    sourceDir = sourceDir + "/*.log"
    return glob.glob(sourceDir)


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


def getProtocols(host):
    doInterrogate(host, "show ip proto")


def getPlatform(host):
    doInterrogate(host, "show ver")


def getSTPMode(host):
    out = doInterrogate(host, "show spann sum")
    hostname = host["ip"]
    curList = []
    stpModes = []
    for line in out.split("\n"):
        print(line)
        if line.startswith('Switch is in'):
            curList.append(hostname)
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


def printTCNs(hosts):
    list = []
    "Calling getTCN"
    print(hosts)
    for host in hosts:
        vlans = getTCNs(host)
        if len(vlans) > 0:
            list.append(vlans)
        else:
             print("No Active VLANs")
        for entry in list:
            print(host['ip'])
            printTable(entry, ['VLAN', 'TCN Count'])
            list = []


def printSTP(hosts):
    list = []
    for host in hosts:
        list.append(getSTPMode(host))
    print(list)
    printTable(list, ['Hostname', 'STP Mode', 'Root For', 'Portfast Default', 'BPDUGuard Default', 'Pathcost Method'])


def printTable(myList, headers = None):
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


if __name__ == '__main__':

    directory = 'output'
    password = getpass()
    username = "craigb"

    sw1 = {
        'device_type': 'cisco_ios',
        'host': '192.168.10.1',
        'username': username,
        'password': password,
    }

    ap1 = {
        'device_type': 'cisco_ios',
        'host': '192.168.11.11',
        'username': username,
        'password': password,
    }

    devices = [sw1, ap1]

    f = open("sh_commands.txt", "r")
    config_commands = f.readlines()

    #collectOutput(devices)

    outputs = readOutputs(directory)
    for o in outputs:
        print("-" * 40)
        print(re.search('hostname\s(.*)', o).group())
        print("-" * 40, "\n")
        check_tcns(o, 1)
        check_ospf(o)

    #check_tcns()