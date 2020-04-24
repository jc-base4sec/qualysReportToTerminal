# Professional Services Qualys Report Tool
# Organization: Base4 Security
# Author: Juan Cruz Tommasi
# Date: 24/04/2020

import os
from tabulate import tabulate
from argparse import ArgumentParser

#INIT DATABASE
fulldatabase = []
matchedLinesList = []
vulns_db = []
ipaddrs = []
hostnames = []
opsystems = []
ports = []
protocols = []
vulns_qids = []
vulns_titles = []
vulns_severity = []
vulns_cves = []
vulns_threat = []
vulns_impact = []
vulns_solution = []
vulns_exploitability = []
vulns_results = []
vuln = ""

def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    if v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean Value Expected')

def RepresentsInt(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def beautyText(text):
    print("#######################################")
    print("# " + text)
    print("#######################################")


parser = ArgumentParser(description='Qualys CSV Scan Parser - Base4 Security')
parser.add_argument('-f', '--filename', type=str, metavar='',required=True, help='report.csv file path')
parser.add_argument('-i', '--issue', type=str, metavar='', required=False, default=False, help='Title of issue or vulnerability')
parser.add_argument('--hostlist', type=str2bool, nargs='?', const=True, default=False, help='Print only host:port')
parser.add_argument('--vulnlist', type=str2bool, nargs='?', const=True, default=False, help='Print Vulnerability List')
parser.add_argument('--titles', type=str2bool, nargs='?', const=True, default=False, help='Print Only Titles List')
parser.add_argument('--full', type=str2bool, nargs='?', const=True, default=False, help='Print all information about vulnerability')
parser.add_argument('-d', '--debug', type=int, metavar='', required=False, help='debug value')
args = parser.parse_args()

filename = args.filename
issue = args.issue

def saveVulnData(filename, issue):
    j = open(filename, 'r')
    for line in j:
        if issue in line:
            matchedLinesList.insert(len(matchedLinesList), line)

    for mline in matchedLinesList:

        mlist = mline.split(",")
        if len(mlist) >= 13:
            #print(mlist[args.debug])
            ipaddrs.insert(len(ipaddrs), mlist[0].strip('"'))
            hostnames.insert(len(hostnames), mlist[1].strip('"'))
            opsystems.insert(len(opsystems), mlist[4].strip('"'))
            ports.insert(len(ports), mlist[12].strip('"'))
            protocols.insert(len(protocols), mlist[13].strip('"'))
            if len(mlist) > 8 and not mlist[8] in fulldatabase:
                fulldatabase.insert(len(fulldatabase), mlist[11]+" - "+mlist[8])

def saveAllVulnsData(filename):
    f = open(filename, 'r')
    for line in f:
        if "host scanned, found vuln" in line:
            vulns_db.insert(len(vulns_db), line)

    for line in vulns_db:
        line = line.split(",")
        if args.titles == True:
            if not line[8] in fulldatabase:
                fulldatabase.insert(len(fulldatabase), line[11]+" - "+line[7]+" - "+line[8])
        vulns_qids.insert(len(vulns_db), line[7])
        vulns_titles.insert(len(vulns_db), line[8])
        vulns_severity.insert(len(vulns_db), line[11])
        if len(line) > 22:
            vulns_cves.insert(len(vulns_db), line[23])
            vulns_threat.insert(len(vulns_db), line[24])
            vulns_impact.insert(len(vulns_db), line[25])

saveAllVulnsData(filename)

if args.hostlist == False and args.full == False and args.titles == True:
    fulldatabase = sorted(set(fulldatabase), reverse=True)
    for titulos in fulldatabase:
        print(titulos)
    exit()


#AKA OTRO
if args.vulnlist == False and issue != False or args.hostlist == True:
    saveVulnData(filename, issue)
    fulldatabase = sorted(set(fulldatabase), reverse=True)
    hosttable = {"IP Address":ipaddrs,"Port":ports,"Protocol":protocols,"Operating System":opsystems, "Hostname":hostnames}

    if args.hostlist == False and args.full == False:
        print("\n[*] "+ issue)
        print(tabulate(hosttable, showindex="always"))

    if args.hostlist == True and args.full == False:
        print("\n[*] "+ issue)
        print("[!] Affected Hosts\n")
        for i in range(len(ipaddrs)):
            print(ipaddrs[i]+":"+ports[i])

if args.full == True and args.titles == True and issue == False and args.hostlist == False and args.vulnlist == False:
    fulldatabase = sorted(set(fulldatabase), reverse=True)
    f = open(filename, 'r')
    for titulo in fulldatabase:
        titulo = titulo.strip(" ").split("-")
        titulo = titulo[2]
        for lines in f:
            if titulo in lines:
                print(lines)
