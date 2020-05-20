# Professional Services Qualys Report Tool
# Organization: Base4 Security
# Author: Juan Cruz Tommasi
# Date: 24/04/2020

import os
import requests
from tabulate import tabulate
from argparse import ArgumentParser
from googletrans import Translator

#INIT DATABASE
fulldatabase = []
matchedLinesList = []
vulns_db = []
ipaddrs = []
hostnames = []
opsystems = []
ports = []
protocols = []
cves = []
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
parser.add_argument('--titles', type=str2bool, nargs='?', const=True, default=False, help='Print Only Titles List')
parser.add_argument('--full', type=str2bool, nargs='?', const=True, default=False, help='Print all information about vulnerability')
parser.add_argument('-c','--cve', type=str, nargs='?', required=False, default=False, help='Print all information about vulnerability from cve')
parser.add_argument('-d', '--debug', type=int, metavar='', required=False, help='debug value')
args = parser.parse_args()

filename = args.filename
issue = args.issue

def printVulnFullBanner():
    print(  "\n\n┌─┐┬ ┬┬  ┬    ┬─┐┌─┐┌─┐┌─┐┬─┐┌┬┐\n"
            "├┤ │ ││  │    ├┬┘├┤ ├─┘│ │├┬┘ │\n"
            "└  └─┘┴─┘┴─┘  ┴└─└─┘┴  └─┘┴└─ ┴\n")

def translateFromGoogle(text):
    translator = Translator(service_urls=['translate.google.com.ar'])
    translated = translator.translate(text, dest='es', src='en')
    return translated.text

def cveFullInfo(api_response, issue):
    #all data of vuln
    api_response = api_response.json()
    results = api_response.get('result')

    #divided
    entry = results[0].get('entry')
    vulninfo = results[0].get('vulnerability')
    advisory = results[0].get('advisory')
    #1st entry
    title = entry['title']
    summary = entry['summary']
    affected = entry['details']['affected']
    vulnerability = entry['details']['vulnerability']
    impact = entry['details']['impact']
    exploit = entry['details']['exploit']
    countermeasure = entry['details']['countermeasure']
    sources = entry['details']['sources']
    #2nd vulninfo
    risk = vulninfo['risk']['name']
    classes = vulninfo['class']
    cwe = vulninfo['cwe']
    cvss3_basescore = vulninfo['cvss3']['meta']['basescore']
    cvss3_basevector = vulninfo['cvss3']['vuldb']['basevector']
    nvd_url = 'https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector='+cvss3_basevector+'&version=3.1'

    printVulnFullBanner()
    print("Título de Qualys: %s" % (issue))
    print("Título de VulnDb: %s" % (title))
    print("Clasificación: %s" % (classes))
    print("CWE: %s" % (cwe))
    print("CVSS: %s" % (cvss3_basescore))
    print("URL CVSS 3.1: %s" % (nvd_url))
    print("\n[*] Proceso: \n%s" % (translateFromGoogle(summary)))
    print("\nExplotacion: \n%s" % (translateFromGoogle(exploit)))
    print("\n[!] Impacto: \n%s" % (translateFromGoogle(impact)))
    print("\n[#] Recomendación: \n%s" % (translateFromGoogle(countermeasure)))
    print("[+] Mas información: \n%s\n" % (translateFromGoogle(sources)))
    if advisory.get('person', False) != False and advisory.get('company', False) != False:
        advisory_text = "obtener mas información sobre la vulnerabilidad en %s - O buscando información sobre el autor del hallazgo: %s at %s" % (advisory['url'],advisory['person']['name'],advisory['company']['name'])
        print("O tambien puede %s\n" % advisory_text)

def getCVEnfo(cve):
    # Add your personal API key here
    personalApiKey = '7a08875b4df6b2b6dd8a97944181b82c'
    # Set HTTP Header
    headers = {'X-VulDB-ApiKey': personalApiKey}
    # URL VulDB endpoint
    url = 'https://vuldb.com/?api'
    postData = {'advancedsearch': 'cve:'+cve,'details' : 1}
    # Get API response
    response = requests.post(url,headers=headers,data=postData)
    return response

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
            cves.insert(len(cves), mlist[23].strip('"') + " - " + mlist[24].strip('"'))
            if len(mlist) > 8 and not mlist[8] in fulldatabase:
                fulldatabase.insert(len(fulldatabase), mlist[11]+" - "+mlist[8])

def getCVEfromDB(string):
    cvefull = string.split('"')
    return cvefull

def checkForCVEsubString(string):
    if "CVE" in string:
        return string
    else:
        return ""

def saveAllVulnsData(filename):
    f = open(filename, 'r')
    for line in f:
        if "host scanned, found vuln" in line:
            vulns_db.insert(len(vulns_db), line)

    for line in vulns_db:
        line = line.split(",")
        if args.titles == True or args.full == True:
            if not line[8] in fulldatabase:
                fulldatabase.insert(len(fulldatabase), line[11]+ " - " + line[7] + " - " + line[8] + " - " + checkForCVEsubString(line[23]) + " " + checkForCVEsubString(line[24]))
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
if issue != False or args.hostlist == True:
    saveVulnData(filename, issue)
    fulldatabase = sorted(set(fulldatabase), reverse=True)
    hosttable = {"IP Address":ipaddrs,"Port":ports,"Protocol":protocols,"Operating System":opsystems, "Hostname":hostnames, "CVE/Version":cves}

    if args.hostlist == False and args.full == False:
        print("\n[*] "+ issue)
        print(tabulate(hosttable, showindex="always"))

    if args.hostlist == True and args.full == False:
        print("\n[*] "+ issue)
        print("[!] Affected Hosts\n")
        for i in range(len(ipaddrs)):
            print(ipaddrs[i]+":"+ports[i])

if args.full == True and args.issue != False and args.hostlist == False:
    fulldatabase = sorted(set(fulldatabase), reverse=True)
    for titulo in fulldatabase:
        if issue in titulo and "CVE" in titulo:
            cve = getCVEfromDB(titulo)
            cve = cve[7]
            API_info = getCVEnfo(cve)
            cveFullInfo(API_info, issue)
        else:
            print("\n[!!] Se desconoce CVE para la vulnerabilidad ingresada, un reporte completo no puede ser generado sin un identificador CVE\n")
            exit()

if args.cve != False:
    cve = args.cve
    API_info = getCVEnfo(cve)
    cveFullInfo(API_info, issue)
