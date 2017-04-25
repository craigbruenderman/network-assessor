#!/usr/bin/env python

import sys
import re
import glob
import os
import yaml
import openSSH
import csv
import ipaddress
import pickle
from tabulate import tabulate


class NetworkDevice(object):
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password


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


def getHostNames(hosts):
    for host in hosts:
        openSSH.doInterrogate(host, "show hostname")


def getCDPNeighbors(host):
    out = openSSH.doInterrogate(host, "show cdp neigh")
    out = out.strip()
    out = out.split("\n")
    print "Output:"
    print out
    print "\n"
    iterator = iter(out)
    for line in iterator:
        if line.startswith("Device ID") or line.startswith('Device-ID'):
            neighbor = next(iterator).strip()
            print neighbor

#'CBTS-LouLab-R1.loulab-cbts.net\r', 'Gig 1/0/43        161              R I   ASR1001-X Gig 0/0/1\r',
# '5548-1(SSI153207R5)\r', 'Ten 1/1/1         171            R S I C N5K-C5548 Eth 1/7\r', 
# '5548-1(SSI153207R5)\r', 'Gig 1/0/1         136            R S I C N5K-C5548 mgmt0\r', 
# '5548-2(SSI153207CN)\r', 'Gig 1/0/2         136            R S I C N5K-C5548 mgmt0\r', 
# 'localhost        Gig 1/0/14        170               S    VMware ES vmnic0\r', 
# 'localhost        Gig 1/0/16        170               S    VMware ES vmnic1\r',
# 'Lou-Lab-Mgmt#']


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
    print openSSH.doInterrogate(host, "show vpc")


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
        print line
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
    print hosts
    for host in hosts:
        vlans = getTCNs(host)
        if len(vlans) > 0:
            list.append(vlans)
        else:
             print "No Active VLANs"   
        for entry in list:
            print host['ip']
            printTable(entry, ['VLAN', 'TCN Count'])
            list = []
    
    
def printSTP(hosts):
    list = []
    for host in hosts:
        list.append(getSTPMode(host))
    print list
    printTable(list, ['Hostname', 'STP Mode', 'Root For', 'Portfast Default', 'BPDUGuard Default', 'Pathcost Method'])


def printTable(myList, headers = None):
    if headers:
        print tabulate(myList, headers = headers, tablefmt="fancy_grid")
    else:
        print tabulate(myList, tablefmt="fancy_grid")


def openFile(fname):
    try:
        fhand = open(fname)
        return fhand
    except:
        print 'Unable to open file', fname
        sys.exit(1)


def writeCSV(hosts):
    with open('mycsvfile.csv', 'wb') as f:  # Just use 'w' mode in 3.x
        fieldnames = hosts[1].keys()
        print fieldnames
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for host in hosts:
            w.writerow(host)



if __name__ == '__main__':

    # Setup list of devices
    # This is a dictionary
    hostDict = readHosts()
    hostList = []

    #Create a list containing hosts as NetworkDevice objects
    for k, v in hostDict.iteritems():
        hostObj = NetworkDevice(k, v["username"], v["password"])
        hostList.append(hostObj)

    printHosts(hostList)
    #getHostNames(hostList)

    for host in hostList:
        getCDPNeighbors(host)